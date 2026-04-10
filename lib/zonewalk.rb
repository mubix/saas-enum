# frozen_string_literal: true

require "resolv"
require "timeout"
require "open3"

# NOTE: Zone walking requires the `dig` command (from dnsutils/bind-utils)
# because Ruby's Resolv::DNS does not expose NSEC records from the authority
# section of NXDOMAIN responses. This is the only feature in saas-enum that
# requires an external tool. All other features (TXT, CNAME, MX, NS, HTML)
# use pure Ruby.

module SaasEnum
  # DNSSEC NSEC zone walker.
  #
  # NSEC records chain through all names in a DNS zone in canonical order.
  # By querying for names and reading the NSEC "next domain" field, we can
  # enumerate every name in the zone without brute-forcing.
  #
  # This only works when:
  #   - The zone has DNSSEC enabled with NSEC (not NSEC3)
  #   - The nameserver does not implement RFC4470 "minimal covering" (black lies)
  #
  # Discovered subdomains are checked against CnameEngine rules.
  class ZoneWalker
    MAX_QUERIES = 500

    attr_reader :discovered, :errors

    def initialize(domain, nameserver: nil)
      @domain = domain.downcase.chomp(".")
      @nameserver = nameserver || "8.8.8.8"
      @discovered = []
      @errors = []
      @seen = {}
    end

    # Walk the zone and return discovered subdomain names.
    def walk
      @discovered = []
      @errors = []
      @seen = {}

      unless dig_available?
        @errors << "Zone walking requires 'dig' (dnsutils/bind-utils). Install it or remove --zonewalk."
        return @discovered
      end

      # Detect DNSSEC type
      nsec_type = detect_dnssec_type
      unless nsec_type == :nsec
        case nsec_type
        when :nsec3
          @errors << "Zone uses NSEC3 (hashed names). Zone walking not possible for this zone."
        when :black_lies
          @errors << "Zone uses NSEC with minimal covering (black lies). Zone walking returns synthetic records only."
        when :none
          @errors << "Zone does not appear to have DNSSEC enabled."
        end
        return @discovered
      end

      # Walk using the zone's authoritative nameserver for best results
      auth_ns = find_authoritative_ns
      ns_to_use = auth_ns || @nameserver

      current = @domain
      query_count = 0

      loop do
        break if query_count >= MAX_QUERIES

        next_name = query_nsec_next(current, ns_to_use)
        break unless next_name

        query_count += 1
        next_name = next_name.downcase.chomp(".")

        # Stop if we've looped back
        break if @seen[next_name]

        # Stop if we've left the zone
        break unless next_name.end_with?(".#{@domain}") || next_name == @domain

        @seen[next_name] = true

        # Record subdomains (not the apex)
        if next_name != @domain && next_name.end_with?(".#{@domain}")
          @discovered << next_name
        end

        current = next_name
      end

      @discovered
    end

    # Check discovered subdomains against CNAME rules.
    def check_against_rules(cname_engine)
      matches = []

      @discovered.each do |fqdn|
        cname_target, _ips = resolve_cname(fqdn)
        next unless cname_target

        cname_engine.rules.each do |rule|
          if rule.cname_match?(cname_target)
            matches << {
              provider:    rule.name,
              category:    rule.category,
              description: rule.description,
              website:     rule.website,
              record:      "[ZONEWALK+CNAME] #{fqdn} -> #{cname_target}",
              impact:      rule.impact,
              reference:   nil,
              source:      :zonewalk,
            }
            break
          end
        end
      end

      matches
    end

    private

    def detect_dnssec_type
      # Step 1: Check if DNSSEC is enabled (look for DNSKEY)
      dnskey_out, _ = run_dig("+dnssec +noall +answer", "DNSKEY", @domain)
      unless dnskey_out.include?("DNSKEY")
        return :none
      end

      # Step 2: Query a non-existent name to see NSEC vs NSEC3 in authority
      probe = "saas-enum-zw-probe-#{rand(99999)}.#{@domain}"
      auth_out, _ = run_dig("+dnssec +noall +authority", "A", probe)

      if auth_out.include?("NSEC3")
        return :nsec3
      elsif auth_out.include?("NSEC")
        # Check for black lies (RFC4470): the NSEC record covers only the
        # queried name itself, meaning next_name = \000.probe
        # This is synthetic and not useful for zone walking
        auth_out.each_line do |line|
          next unless line.include?("NSEC") && !line.include?("RRSIG")
          parts = line.strip.split(/\s+/)
          nsec_idx = parts.index("NSEC")
          next unless nsec_idx
          owner = parts[0].downcase.chomp(".")
          next_name = parts[nsec_idx + 1]&.downcase&.chomp(".")
          # Black lies: owner == probe and next_name starts with \000.probe
          if owner == probe.downcase && next_name&.start_with?("\\000.#{probe.downcase}")
            return :black_lies
          end
        end
        return :nsec
      end

      :none
    end

    def find_authoritative_ns
      ns_out, _ = run_dig("+noall +authority", "NS", @domain)
      ns_out.each_line do |line|
        parts = line.strip.split(/\s+/)
        if parts.include?("NS")
          ns_idx = parts.index("NS")
          return parts[ns_idx + 1]&.chomp(".")
        end
      end
      nil
    rescue StandardError
      nil
    end

    def query_nsec_next(name, nameserver)
      # To get NSEC records, we need an NXDOMAIN response.
      # We query for a name unlikely to exist that sorts near our current position.
      probe = "zz--saasenum-walk.#{name}"

      auth_out, _ = run_dig("+tcp +dnssec +noall +authority", "A", probe, nameserver)

      # Parse all NSEC records from the authority section
      nsec_entries = []
      auth_out.each_line do |line|
        next unless line.include?("\tNSEC\t") || (line.include?(" NSEC ") && !line.include?("NSEC3") && !line.include?("RRSIG"))
        parts = line.strip.split(/\s+/)
        nsec_idx = parts.index("NSEC")
        next unless nsec_idx
        owner = parts[0].downcase.chomp(".")
        next_name = parts[nsec_idx + 1]&.chomp(".")
        nsec_entries << { owner: owner, next_name: next_name } if next_name
      end

      # Find the NSEC record whose owner matches or covers our current name
      current_normalized = name.downcase.chomp(".")

      # First, look for an NSEC whose owner equals the current name
      nsec_entries.each do |entry|
        if entry[:owner] == current_normalized
          return entry[:next_name] unless entry[:next_name].start_with?("\\000")
        end
      end

      # Otherwise, take the first NSEC whose next_name is in the zone
      nsec_entries.each do |entry|
        next_n = entry[:next_name]
        if next_n && !next_n.start_with?("\\000") &&
           (next_n.end_with?(".#{@domain}") || next_n == @domain)
          return next_n
        end
      end

      nil
    rescue StandardError => e
      @errors << "NSEC query failed for #{name}: #{e.message}"
      nil
    end

    def resolve_cname(hostname)
      Timeout.timeout(5) do
        resolver = Resolv::DNS.new(nameserver: @nameserver)
        cnames = resolver.getresources(hostname, Resolv::DNS::Resource::IN::CNAME)
        if cnames.any?
          target = cnames.first.name.to_s
          resolver.close
          return [target, []]
        end
        resolver.close
        [nil, []]
      end
    rescue StandardError
      [nil, []]
    end

    def dig_available?
      _, status = Open3.capture2("which", "dig")
      status.success?
    rescue StandardError
      false
    end

    def run_dig(flags, record_type, name, nameserver = nil)
      ns = nameserver || @nameserver
      cmd = "dig #{flags} #{record_type} #{name} @#{ns} 2>/dev/null"
      output, status = Open3.capture2(cmd)
      [output, status]
    end
  end
end
