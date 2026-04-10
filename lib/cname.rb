# frozen_string_literal: true

require "resolv"
require "yaml"
require "timeout"

module SaasEnum
  class CnameRule
    attr_reader :name, :category, :description, :website, :impact,
                :cname_targets, :subdomains_to_check, :mx_targets,
                :ns_targets, :ip_ranges

    def initialize(data)
      @name                = data["name"]
      @category            = data["category"]
      @description         = data["description"]
      @website             = data["website"]
      @impact              = data["impact"]
      @cname_targets       = data["cname_targets"] || []
      @subdomains_to_check = data["subdomains_to_check"] || []
      @mx_targets          = data["mx_targets"] || []
      @ns_targets          = data["ns_targets"] || []
      @ip_ranges           = data["ip_ranges"] || []
    end

    # Check if a CNAME destination matches any of this rule's targets.
    def cname_match?(cname_destination)
      @cname_targets.any? { |target| cname_destination.downcase.end_with?(target.downcase) }
    end

    # Check if an MX record matches any of this rule's MX targets.
    def mx_match?(mx_host)
      @mx_targets.any? { |target| mx_host.downcase.end_with?(target.downcase) }
    end

    # Check if an NS record matches any of this rule's NS targets.
    def ns_match?(ns_host)
      @ns_targets.any? { |target| ns_host.downcase.end_with?(target.downcase) }
    end
  end

  class CnameEngine
    attr_reader :rules, :errors

    TIMEOUT = 5 # seconds per DNS lookup

    def initialize
      @rules = []
      @errors = []
    end

    def load_file(path)
      data = YAML.safe_load_file(path, permitted_classes: [Symbol])
      data.each { |entry| @rules << CnameRule.new(entry) }
      self
    end

    def load_directory(dir)
      Dir.glob(File.join(dir, "saas_cnames.yml")).each { |f| load_file(f) }
      self
    end

    # Run all CNAME checks against a target domain.
    # Returns an array of match hashes compatible with TXT match output.
    def check(domain)
      @errors = []
      matches = []

      # Phase 1: Check subdomains for CNAME matches
      matches.concat(check_subdomains(domain))

      # Phase 2: Check MX records
      matches.concat(check_mx(domain))

      # Phase 3: Check NS delegations for known subdomains
      matches.concat(check_ns(domain))

      matches
    end

    private

    # Resolve a hostname and follow the CNAME chain.
    # Returns [final_cname, resolved_ips] or [nil, []] on failure.
    def resolve_cname(hostname)
      Timeout.timeout(TIMEOUT) do
        resolver = Resolv::DNS.new(nameserver: "8.8.8.8")
        # Try CNAME first
        cnames = resolver.getresources(hostname, Resolv::DNS::Resource::IN::CNAME)
        if cnames.any?
          # Follow the chain (one level is usually enough)
          target = cnames.first.name.to_s
          resolver.close
          return [target, []]
        end

        # No CNAME, try A record (may still be pointing to provider IPs)
        a_records = resolver.getresources(hostname, Resolv::DNS::Resource::IN::A)
        ips = a_records.map { |r| r.address.to_s }
        resolver.close
        [nil, ips]
      end
    rescue Timeout::Error, Resolv::ResolvError, StandardError
      [nil, []]
    end

    def check_subdomains(domain)
      matches = []
      checked = {}

      @rules.each do |rule|
        next if rule.subdomains_to_check.empty? && rule.cname_targets.empty?

        rule.subdomains_to_check.each do |sub|
          fqdn = "#{sub}.#{domain}"
          next if checked[fqdn]

          checked[fqdn] = true
          cname_target, _ips = resolve_cname(fqdn)
          next unless cname_target

          if rule.cname_match?(cname_target)
            matches << build_match(rule, "CNAME", "#{fqdn} -> #{cname_target}")
          end
        end
      end

      matches
    end

    def check_mx(domain)
      matches = []
      mx_hosts = lookup_mx(domain)
      return matches if mx_hosts.empty?

      @rules.each do |rule|
        next if rule.mx_targets.empty?

        mx_hosts.each do |mx_host|
          if rule.mx_match?(mx_host)
            matches << build_match(rule, "MX", "#{domain} MX #{mx_host}")
            break # One match per rule is enough
          end
        end
      end

      matches
    end

    def check_ns(domain)
      matches = []

      # Check NS for common delegated subdomains
      subdomains_with_ns = []
      @rules.each do |rule|
        next if rule.ns_targets.empty?

        rule.subdomains_to_check.each do |sub|
          subdomains_with_ns << { fqdn: "#{sub}.#{domain}", rule: rule }
        end
      end

      checked = {}
      subdomains_with_ns.each do |entry|
        fqdn = entry[:fqdn]
        next if checked[fqdn]

        checked[fqdn] = true
        ns_hosts = lookup_ns(fqdn)
        next if ns_hosts.empty?

        rule = entry[:rule]
        ns_hosts.each do |ns_host|
          if rule.ns_match?(ns_host)
            matches << build_match(rule, "NS", "#{fqdn} NS #{ns_host}")
            break
          end
        end
      end

      matches
    end

    def lookup_mx(domain)
      Timeout.timeout(TIMEOUT) do
        resolver = Resolv::DNS.new(nameserver: "8.8.8.8")
        records = resolver.getresources(domain, Resolv::DNS::Resource::IN::MX)
        hosts = records.map { |r| r.exchange.to_s }
        resolver.close
        hosts
      end
    rescue Timeout::Error, Resolv::ResolvError, StandardError
      []
    end

    def lookup_ns(domain)
      Timeout.timeout(TIMEOUT) do
        resolver = Resolv::DNS.new(nameserver: "8.8.8.8")
        records = resolver.getresources(domain, Resolv::DNS::Resource::IN::NS)
        hosts = records.map { |r| r.name.to_s }
        resolver.close
        hosts
      end
    rescue Timeout::Error, Resolv::ResolvError, StandardError
      []
    end

    def build_match(rule, record_type, record_value)
      {
        provider:    rule.name,
        category:    rule.category,
        description: rule.description,
        website:     rule.website,
        record:      "[#{record_type}] #{record_value}",
        impact:      rule.impact,
        reference:   nil,
        source:      :cname,
      }
    end
  end
end
