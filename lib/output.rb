# frozen_string_literal: true

require "json"

module SaasEnum
  module Output
    module_function

    # ANSI color helpers. Only emit codes when writing to a TTY.
    def c(code, str, stream)
      tty?(stream) ? "\e[#{code}m#{str}\e[0m" : str
    end

    def tty?(stream)
      stream.respond_to?(:isatty) && stream.isatty
    end

    # Print results for a single domain.
    def print_table(domain, matches, resolver_errors: [], stream: $stdout)
      if matches.empty?
        stream.puts ""
        stream.puts "  #{c("1", domain, stream)}: no SaaS verification records found."
        print_errors(resolver_errors, stream: stream)
        return
      end

      # Group by provider, collecting all records
      grouped = {}
      matches.sort_by { |m| [m[:category] || "", m[:provider]] }.each do |m|
        key = m[:provider]
        grouped[key] ||= { meta: m, records: [] }
        grouped[key][:records] << m[:record]
      end

      provider_count = grouped.length
      record_count = matches.length

      stream.puts ""
      stream.puts c("2", "  ══════════════════════════════════════════════════════════════════════════", stream)
      stream.puts "  #{c("1", domain, stream)}  #{c("2", "// #{provider_count} providers found (#{record_count} records)", stream)}"
      stream.puts c("2", "  ══════════════════════════════════════════════════════════════════════════", stream)

      grouped.each_value do |entry|
        m = entry[:meta]
        records = entry[:records]

        stream.puts ""
        # Provider name + category tag
        tag = c("36", "[#{m[:category]}]", stream)
        stream.puts "  #{c("1;33", "┌ #{m[:provider]}", stream)}  #{tag}"

        # Description
        if m[:description]
          stream.puts "  #{c("2", "│", stream)} #{m[:description]}"
        end

        # Impact
        if m[:impact]
          label = c("1;31", "IMPACT:", stream)
          stream.puts "  #{c("2", "│", stream)} #{label} #{m[:impact]}"
        end

        # Records
        records.each_with_index do |rec, i|
          connector = (i == records.length - 1) ? "└" : "├"
          stream.puts "  #{c("2", connector, stream)} #{c("2", "rec:", stream)} #{truncate(rec, 68)}"
        end
      end

      stream.puts ""
      stream.puts c("2", "  ──────────────────────────────────────────────────────────────────────────", stream)
      stream.puts "  #{c("1;32", "#{provider_count}", stream)} provider(s) detected across #{c("1;32", "#{record_count}", stream)} verification record(s)"

      print_errors(resolver_errors, stream: stream)
    end

    # Print unmatched TXT records for visibility.
    def print_unmatched(domain, unmatched, stream: $stdout)
      return if unmatched.empty?

      stream.puts ""
      stream.puts "  #{c("2", "Unmatched TXT records (#{unmatched.length}):", stream)}"
      unmatched.each do |r|
        stream.puts "  #{c("2", "  #{truncate(r, 72)}", stream)}"
      end
    end

    # Build a JSON-serializable result hash for one domain.
    def to_hash(domain, matches, unmatched, resolver_errors: [])
      {
        domain:     domain,
        providers:  matches.map { |m|
          {
            name:        m[:provider],
            category:    m[:category],
            description: m[:description],
            impact:      m[:impact],
            website:     m[:website],
            record:      m[:record],
            reference:   m[:reference],
          }
        },
        unmatched_records: unmatched,
        resolver_errors:   resolver_errors,
      }
    end

    # Print JSON output for all results.
    def print_json(results, stream: $stdout)
      stream.puts JSON.pretty_generate(results)
    end

    def print_errors(errors, stream: $stdout)
      return if errors.empty?

      stream.puts ""
      stream.puts "  Resolver warnings:"
      errors.each do |e|
        stream.puts "    [#{e[:resolver]}] #{e[:error]}"
      end
    end

    def truncate(str, max)
      str.length > max ? "#{str[0, max - 3]}..." : str
    end
  end
end
