# frozen_string_literal: true

require "json"
require "cgi"

module SaasEnum
  module HtmlReport
    module_function

    def generate(results, output_path)
      html = build_html(results)
      File.write(output_path, html)
    end

    def build_html(results)
      total_providers = results.sum { |r| r[:providers].map { |p| p[:name] }.uniq.length }
      total_records = results.sum { |r| r[:providers].length }
      total_domains = results.length
      timestamp = Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")

      domain_sections = results.map { |r| build_domain_section(r) }.join("\n")

      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>SaaS Enum Report</title>
          <style>
            :root {
              --bg: #0d1117;
              --surface: #161b22;
              --surface-hover: #1c2129;
              --border: #30363d;
              --text: #e6edf3;
              --text-dim: #8b949e;
              --accent: #f0883e;
              --red: #f85149;
              --green: #3fb950;
              --blue: #58a6ff;
              --purple: #bc8cff;
              --yellow: #d29922;
              --cyan: #39d2c0;
            }

            * { box-sizing: border-box; margin: 0; padding: 0; }

            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
              background: var(--bg);
              color: var(--text);
              line-height: 1.6;
              padding: 0;
            }

            .header {
              background: linear-gradient(135deg, #1a1e24 0%, #0d1117 100%);
              border-bottom: 1px solid var(--border);
              padding: 2rem 2rem 1.5rem;
            }

            .header h1 {
              font-size: 1.75rem;
              font-weight: 600;
              color: var(--accent);
              margin-bottom: 0.25rem;
            }

            .header .subtitle {
              color: var(--text-dim);
              font-size: 0.9rem;
            }

            .stats {
              display: flex;
              gap: 2rem;
              margin-top: 1.25rem;
              flex-wrap: wrap;
            }

            .stat {
              text-align: center;
            }

            .stat .number {
              font-size: 2rem;
              font-weight: 700;
              color: var(--accent);
              display: block;
              line-height: 1.2;
            }

            .stat .label {
              font-size: 0.75rem;
              color: var(--text-dim);
              text-transform: uppercase;
              letter-spacing: 0.05em;
            }

            .container {
              max-width: 1200px;
              margin: 0 auto;
              padding: 1.5rem 2rem;
            }

            .domain-section {
              margin-bottom: 2rem;
            }

            .domain-header {
              font-size: 1.25rem;
              font-weight: 600;
              color: var(--blue);
              padding: 0.75rem 0;
              border-bottom: 2px solid var(--border);
              margin-bottom: 1rem;
            }

            .domain-header .count {
              font-weight: 400;
              color: var(--text-dim);
              font-size: 0.9rem;
            }

            .provider-card {
              background: var(--surface);
              border: 1px solid var(--border);
              border-radius: 8px;
              margin-bottom: 0.75rem;
              overflow: hidden;
              transition: border-color 0.15s;
            }

            .provider-card:hover {
              border-color: #484f58;
            }

            .provider-top {
              display: flex;
              align-items: center;
              gap: 0.75rem;
              padding: 0.875rem 1rem;
              cursor: pointer;
            }

            .provider-top:hover {
              background: var(--surface-hover);
            }

            .provider-name {
              font-weight: 600;
              font-size: 1rem;
              color: var(--text);
              flex-grow: 1;
            }

            .provider-name a {
              color: inherit;
              text-decoration: none;
            }

            .provider-name a:hover {
              color: var(--blue);
            }

            .category-badge {
              font-size: 0.7rem;
              padding: 0.15rem 0.5rem;
              border-radius: 10px;
              font-weight: 500;
              text-transform: uppercase;
              letter-spacing: 0.03em;
              white-space: nowrap;
            }

            .record-count {
              font-size: 0.75rem;
              color: var(--text-dim);
              white-space: nowrap;
            }

            .chevron {
              color: var(--text-dim);
              transition: transform 0.2s;
              font-size: 0.8rem;
            }

            .provider-card.open .chevron {
              transform: rotate(90deg);
            }

            .provider-details {
              display: none;
              padding: 0 1rem 1rem;
              border-top: 1px solid var(--border);
            }

            .provider-card.open .provider-details {
              display: block;
            }

            .detail-section {
              margin-top: 0.75rem;
            }

            .detail-label {
              font-size: 0.7rem;
              text-transform: uppercase;
              letter-spacing: 0.05em;
              color: var(--text-dim);
              margin-bottom: 0.25rem;
              font-weight: 600;
            }

            .description {
              color: var(--text);
              font-size: 0.875rem;
            }

            .impact {
              color: var(--red);
              font-size: 0.875rem;
              line-height: 1.5;
            }

            .impact.dangling {
              color: var(--yellow);
            }

            .record-list {
              list-style: none;
            }

            .record-list li {
              font-family: 'SF Mono', 'Fira Code', 'Fira Mono', Menlo, monospace;
              font-size: 0.75rem;
              color: var(--text-dim);
              padding: 0.3rem 0.5rem;
              background: var(--bg);
              border-radius: 4px;
              margin-bottom: 0.25rem;
              overflow-x: auto;
              white-space: nowrap;
            }

            .record-list li .rec-type {
              color: var(--cyan);
              font-weight: 600;
            }

            .footer {
              text-align: center;
              padding: 2rem;
              color: var(--text-dim);
              font-size: 0.8rem;
              border-top: 1px solid var(--border);
            }

            .footer a {
              color: var(--blue);
              text-decoration: none;
            }

            /* Category colors */
            .cat-identity { background: #2d1f3d; color: #bc8cff; }
            .cat-collaboration { background: #1a2a1a; color: #3fb950; }
            .cat-communication { background: #1a2a35; color: #58a6ff; }
            .cat-devtools { background: #2a2a1a; color: #d29922; }
            .cat-security { background: #2d1a1a; color: #f85149; }
            .cat-crm { background: #1a2a2a; color: #39d2c0; }
            .cat-email { background: #2a1a2a; color: #f778ba; }
            .cat-monitoring { background: #2a2a1a; color: #d29922; }
            .cat-cloud { background: #1a1f2d; color: #58a6ff; }
            .cat-payments { background: #1f2d1a; color: #3fb950; }
            .cat-compliance { background: #2d1f1a; color: #f0883e; }
            .cat-hr { background: #2d1a2a; color: #f778ba; }
            .cat-analytics { background: #1a2d2a; color: #39d2c0; }
            .cat-social { background: #1a1a2d; color: #58a6ff; }
            .cat-pki { background: #2d2a1a; color: #d29922; }
            .cat-it_management { background: #1a2a35; color: #58a6ff; }
            .cat-storage { background: #1a2a1a; color: #3fb950; }
            .cat-video { background: #2a1a1a; color: #f85149; }
            .cat-support { background: #1a2d2a; color: #39d2c0; }
            .cat-cms { background: #2d1f3d; color: #bc8cff; }
            .cat-automation { background: #2a2a1a; color: #d29922; }
            .cat-design { background: #2d1a2a; color: #f778ba; }
            .cat-data { background: #1a2a2a; color: #39d2c0; }
            .cat-project_management { background: #1a2a1a; color: #3fb950; }
            .cat-networking { background: #1a1f2d; color: #58a6ff; }
            .cat-transportation { background: #2a2a1a; color: #d29922; }
            .cat-iot { background: #2d1a1a; color: #f85149; }
            .cat-marketing { background: #2d1f1a; color: #f0883e; }
            .cat-asset_management { background: #1a2d2a; color: #39d2c0; }

            @media (max-width: 768px) {
              .stats { gap: 1rem; }
              .container { padding: 1rem; }
            }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>SaaS Enum Report</h1>
            <div class="subtitle">Generated #{h(timestamp)}</div>
            <div class="stats">
              <div class="stat">
                <span class="number">#{total_domains}</span>
                <span class="label">Domains Scanned</span>
              </div>
              <div class="stat">
                <span class="number">#{total_providers}</span>
                <span class="label">Providers Detected</span>
              </div>
              <div class="stat">
                <span class="number">#{total_records}</span>
                <span class="label">Records Matched</span>
              </div>
            </div>
          </div>

          <div class="container">
            #{domain_sections}
          </div>

          <div class="footer">
            Generated by <a href="https://github.com/mubix/saas-enum">saas-enum</a>
          </div>

          <script>
            document.querySelectorAll('.provider-top').forEach(el => {
              el.addEventListener('click', () => {
                el.closest('.provider-card').classList.toggle('open');
              });
            });
          </script>
        </body>
        </html>
      HTML
    end

    def build_domain_section(result)
      domain = result[:domain]
      providers = result[:providers]

      grouped = {}
      providers.each do |p|
        key = p[:name]
        grouped[key] ||= { meta: p, records: [] }
        grouped[key][:records] << p[:record]
      end

      cards = grouped.values
        .sort_by { |e| [e[:meta][:category] || "", e[:meta][:name]] }
        .map { |e| build_provider_card(e[:meta], e[:records]) }
        .join("\n")

      <<~HTML
        <div class="domain-section">
          <div class="domain-header">
            #{h(domain)}
            <span class="count">#{grouped.length} provider(s), #{providers.length} record(s)</span>
          </div>
          #{cards}
        </div>
      HTML
    end

    def build_provider_card(meta, records)
      cat = meta[:category] || "unknown"
      cat_class = "cat-#{cat.gsub(/\s+/, '_')}"
      is_dangling = meta[:impact]&.start_with?("Dangling")
      impact_class = is_dangling ? "impact dangling" : "impact"

      record_items = records.map do |r|
        rec_str = h(r.to_s)
        if rec_str.start_with?("[CNAME]", "[MX]", "[NS]")
          type, rest = rec_str.split("] ", 2)
          "<li><span class=\"rec-type\">#{type}]</span> #{rest}</li>"
        else
          "<li>#{rec_str}</li>"
        end
      end.join("\n              ")

      <<~HTML
        <div class="provider-card">
          <div class="provider-top">
            <span class="category-badge #{cat_class}">#{h(cat)}</span>
            <span class="provider-name">
              #{meta[:website] ? "<a href=\"#{h(meta[:website])}\" target=\"_blank\" rel=\"noopener\">#{h(meta[:name])}</a>" : h(meta[:name])}
            </span>
            <span class="record-count">#{records.length} record#{records.length == 1 ? '' : 's'}</span>
            <span class="chevron">&#9654;</span>
          </div>
          <div class="provider-details">
            <div class="detail-section">
              <div class="detail-label">Description</div>
              <div class="description">#{h(meta[:description] || '')}</div>
            </div>
            <div class="detail-section">
              <div class="detail-label">Impact</div>
              <div class="#{impact_class}">#{h(meta[:impact] || '')}</div>
            </div>
            <div class="detail-section">
              <div class="detail-label">Records</div>
              <ul class="record-list">
                #{record_items}
              </ul>
            </div>
          </div>
        </div>
      HTML
    end

    def h(str)
      CGI.escapeHTML(str.to_s)
    end
  end
end
