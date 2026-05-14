class Kamal::Cli::App::SslCertificates
  attr_reader :host, :role, :sshkit
  delegate :execute, :info, :upload!, to: :sshkit

  def initialize(host, role, sshkit)
    @host = host
    @role = role
    @sshkit = sshkit
  end

  def run
    if role.running_proxy? && (role.proxy.custom_ssl_certificate? || role.proxy.cloudflare_origin_cert?)
      # Auto-gerar certificados Cloudflare se necessário
      if role.proxy.cloudflare_origin_cert? && !role.proxy.custom_ssl_certificate?
        role.proxy.auto_generate_ssl_certificate!
      end
      
      info "Writing SSL certificates for #{role.name} on #{host}"
      execute *app.create_ssl_directory
      if cert_content = role.proxy.certificate_pem_content
        upload!(StringIO.new(cert_content), role.proxy.host_tls_cert, mode: "0644")
      end
      if key_content = role.proxy.private_key_pem_content
        upload!(StringIO.new(key_content), role.proxy.host_tls_key, mode: "0644")
      end
    end
  end

  private
    def app
      @app ||= KAMAL.app(role: role, host: host)
    end
end
