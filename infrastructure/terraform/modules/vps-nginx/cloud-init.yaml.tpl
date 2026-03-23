#cloud-config
# SPECTER C2 Redirector — VPS cloud-init
# Installs nginx reverse proxy with profile-aware traffic filtering + certbot TLS

package_update: true
package_upgrade: true

packages:
  - nginx
  - certbot
  - python3-certbot-nginx
  - ufw

write_files:
  - path: /etc/nginx/sites-available/specter-redirector
    permissions: '0644'
    content: |
      # SPECTER C2 Redirector — nginx configuration
      # Profile-aware traffic filtering with decoy responses

      # Rate limiting zone
      limit_req_zone $binary_remote_addr zone=c2limit:10m rate=30r/s;

      server {
          listen 80;
          server_name ${server_names};

          # Redirect HTTP to HTTPS (certbot will handle this after cert issuance)
          location / {
              return 301 https://$host$request_uri;
          }

          # ACME challenge for certbot
          location /.well-known/acme-challenge/ {
              root /var/www/html;
          }
      }

      server {
          listen 443 ssl http2;
          server_name ${server_names};

          # TLS will be configured by certbot
          # Placeholder certs until certbot runs
          ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
          ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

          # TLS hardening
          ssl_protocols TLSv1.2 TLSv1.3;
          ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
          ssl_prefer_server_ciphers off;
          ssl_session_timeout 1d;
          ssl_session_cache shared:SSL:10m;
          ssl_session_tickets off;

          # Security headers to blend with legitimate sites
          add_header X-Frame-Options "SAMEORIGIN" always;
          add_header X-Content-Type-Options "nosniff" always;
          add_header Referrer-Policy "no-referrer-when-downgrade" always;

          # Profile-matching location block: forward C2 traffic
          location ~ ${uri_pattern} {
              # Validate C2 identification header
              if ($http_${header_name} !~ "${header_pattern}") {
                  return 404;
              }

              limit_req zone=c2limit burst=10 nodelay;

              proxy_pass ${backend_url};
              proxy_set_header Host $host;
              proxy_set_header X-Real-IP $remote_addr;
              proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
              proxy_set_header X-Forwarded-Proto $scheme;

              # Timeouts for long-polling
              proxy_connect_timeout 60s;
              proxy_send_timeout 120s;
              proxy_read_timeout 120s;

              # Disable buffering for streaming responses
              proxy_buffering off;
          }

          # Default: serve decoy response for non-matching requests
          location / {
              default_type text/html;
              return 404 '${decoy_response}';
          }
      }

  - path: /etc/nginx/conf.d/security.conf
    permissions: '0644'
    content: |
      # Hide nginx version
      server_tokens off;

      # Prevent clickjacking
      add_header X-Frame-Options "SAMEORIGIN" always;

runcmd:
  # Enable firewall
  - ufw allow 22/tcp
  - ufw allow 80/tcp
  - ufw allow 443/tcp
  - ufw --force enable

  # Configure nginx
  - rm -f /etc/nginx/sites-enabled/default
  - ln -sf /etc/nginx/sites-available/specter-redirector /etc/nginx/sites-enabled/
  - nginx -t
  - systemctl restart nginx

  # Obtain TLS certificate
  - certbot --nginx --non-interactive --agree-tos --email ${certbot_email} -d ${certbot_domains} --redirect

  # Set up auto-renewal
  - systemctl enable certbot.timer
  - systemctl start certbot.timer
