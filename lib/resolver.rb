# frozen_string_literal: true

require "resolv"
require "timeout"

# Monkey-patch Resolv::DNS to force TCP for all queries.
#
# By default, Resolv::DNS tries UDP first. UDP responses are limited to 512
# bytes (4096 with EDNS0), and many domains have TXT record sets that exceed
# this. When the response is too large, one of two things happens:
#
#   1. The server sets the TC (truncation) bit. Resolv already handles this
#      and retries via TCP.
#   2. The oversized UDP packet is silently dropped by the network. Resolv
#      sees a timeout, NOT a truncation, and never tries TCP.
#
# Case 2 is what causes the timeouts we see in practice. The fix is to skip
# UDP entirely. Resolv::DNS#fetch_resource already has a clean fallback path:
# when make_udp_requester raises Errno::EACCES, it falls through to TCP.
# We simply force that path.
class Resolv
  class DNS
    private

    alias_method :_original_make_udp_requester, :make_udp_requester

    def make_udp_requester
      raise Errno::EACCES, "forced TCP for reliable TXT record retrieval"
    end
  end
end

module SaasEnum
  # Multi-resolver DNS TXT record lookup with merge and dedup.
  # Queries the system resolver plus multiple public DNS servers,
  # then merges all results into a single deduplicated set.
  #
  # Uses Ruby's Resolv::DNS with a TCP-forced monkey-patch to reliably
  # retrieve large TXT record sets without requiring external tools.
  class Resolver
    RESOLVERS = {
      "system"     => nil, # uses system default
      "google1"    => "8.8.8.8",
      "google2"    => "8.8.4.4",
      "cloudflare" => "1.1.1.1",
      "quad9"      => "9.9.9.9",
      "opendns"    => "208.67.222.222",
    }.freeze

    DEFAULT_TIMEOUT = 10  # seconds per resolver
    DEFAULT_RETRIES = 1

    attr_reader :timeout, :retries, :errors

    def initialize(timeout: DEFAULT_TIMEOUT, retries: DEFAULT_RETRIES)
      @timeout = timeout
      @retries = retries
      @errors = []
    end

    # Lookup TXT records for a domain across all resolvers.
    # Returns a deduplicated array of TXT record strings.
    def lookup(domain)
      all_records = []
      @errors = []

      RESOLVERS.each do |name, nameserver|
        records = query_resolver(domain, name, nameserver)
        all_records.concat(records)
      end

      all_records.uniq
    end

    private

    def query_resolver(domain, name, nameserver)
      attempt = 0
      begin
        attempt += 1
        Timeout.timeout(@timeout) do
          if nameserver
            resolver = Resolv::DNS.new(nameserver: nameserver)
            resources = resolver.getresources(domain, Resolv::DNS::Resource::IN::TXT)
            resolver.close
            resources.map { |r| r.strings.join("") }
          else
            Resolv::DNS.open do |dns|
              resources = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
              resources.map { |r| r.strings.join("") }
            end
          end
        end
      rescue Timeout::Error
        @errors << { resolver: name, domain: domain, error: "timeout after #{@timeout}s" }
        retry if attempt <= @retries
        []
      rescue Resolv::ResolvError => e
        @errors << { resolver: name, domain: domain, error: e.message }
        retry if attempt <= @retries
        []
      rescue StandardError => e
        @errors << { resolver: name, domain: domain, error: "#{e.class}: #{e.message}" }
        []
      end
    end
  end
end
