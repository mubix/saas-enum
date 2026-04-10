# frozen_string_literal: true

require "yaml"

module SaasEnum
  class Rule
    attr_reader :name, :category, :description, :website,
                :match_type, :pattern, :reference, :impact

    def initialize(data)
      @name        = data["name"]
      @category    = data["category"]
      @description = data["description"]
      @website     = data["website"]
      @match_type  = data["match_type"]
      @pattern     = data["pattern"]
      @reference   = data["reference"]
      @impact      = data["impact"]
      @compiled_regex = compile_regex if @match_type == "regex"
    end

    # Test whether a TXT record matches this rule.
    # Returns the matching TXT record string or nil.
    def match(txt_record)
      case @match_type
      when "prefix"
        txt_record if txt_record.start_with?(@pattern)
      when "substring"
        txt_record if txt_record.include?(@pattern)
      when "regex"
        txt_record if @compiled_regex&.match?(txt_record)
      when "spf_include"
        txt_record if txt_record.start_with?("v=spf1") && txt_record.include?(@pattern)
      end
    end

    private

    def compile_regex
      Regexp.new(@pattern)
    rescue RegexpError => e
      warn "WARNING: Invalid regex in rule '#{@name}': #{e.message}"
      nil
    end
  end

  class RuleEngine
    attr_reader :rules

    def initialize
      @rules = []
    end

    # Load rules from a YAML file.
    def load_file(path)
      data = YAML.safe_load_file(path, permitted_classes: [Symbol])
      data.each { |entry| @rules << Rule.new(entry) }
      self
    end

    # Load all YAML files from a directory.
    def load_directory(dir)
      Dir.glob(File.join(dir, "*.yml")).sort.each { |f| load_file(f) }
      self
    end

    # Match all TXT records against all rules.
    # Returns an array of hashes: { provider:, category:, description:, record:, website: }
    def match(txt_records)
      matches = []
      txt_records.each do |record|
        @rules.each do |rule|
          if rule.match(record)
            matches << {
              provider:    rule.name,
              category:    rule.category,
              description: rule.description,
              website:     rule.website,
              record:      record,
              reference:   rule.reference,
              impact:      rule.impact,
            }
          end
        end
      end
      matches
    end
  end
end
