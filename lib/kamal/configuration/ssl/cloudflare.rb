require "net/http"
require "json"
require "uri"

class Kamal::Configuration::Ssl::Cloudflare
  class CloudflareError < StandardError; end
  
  attr_reader :config, :secrets
  
  def initialize(config, secrets)
    @config = config
    @secrets = secrets
  end
  
  def generate_origin_certificate(domains)
    validate_prerequisites!
    
    payload = {
      hostnames: normalize_domains(domains),
      requested_validity: 5475, # 15 anos
      request_type: "origin-rsa"
    }
    
    response = cloudflare_api_call("/client/v4/certificates", method: :post, payload: payload)
    
    unless response["success"]
      errors = response["errors"]&.map { |e| e["message"] }&.join(", ")
      raise CloudflareError, "Falha ao gerar Origin Certificate: #{errors}"
    end
    
    result = response["result"]
    {
      certificate_pem: result["certificate"],
      private_key_pem: result["private_key"]
    }
  end
  
  private
  
  def api_token
    secrets["CF_API_TOKEN"] || ENV["CF_API_TOKEN"]
  end
  
  def validate_prerequisites!
    unless api_token
      raise CloudflareError, "CF_API_TOKEN não encontrado. Configure via secrets ou variável de ambiente."
    end
  end
  
  def normalize_domains(domains)
    # Garantir que temos tanto apex quanto wildcard para compatibilidade
    normalized = Array(domains).flatten.uniq
    
    # Se temos wildcard, incluir também o apex
    normalized.each do |domain|
      if domain.start_with?("*.")
        apex = domain.sub("*.", "")
        normalized << apex unless normalized.include?(apex)
      end
    end
    
    normalized.sort
  end
  
  def cloudflare_api_call(endpoint, method: :get, payload: nil)
    uri = URI("https://api.cloudflare.com#{endpoint}")
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 30
    
    case method
    when :post
      request = Net::HTTP::Post.new(uri)
      request.body = payload.to_json if payload
      request["Content-Type"] = "application/json"
    when :get
      request = Net::HTTP::Get.new(uri)
    else
      raise CloudflareError, "Método HTTP #{method} não suportado"
    end
    
    request["Authorization"] = "Bearer #{api_token}"
    request["User-Agent"] = "kamal-cloudflare-ssl/1.0"
    
    response = http.request(request)
    
    unless response.code.to_i.between?(200, 299)
      raise CloudflareError, "API Cloudflare retornou #{response.code}: #{response.body}"
    end
    
    JSON.parse(response.body)
  rescue JSON::ParserError => e
    raise CloudflareError, "Resposta inválida da API Cloudflare: #{e.message}"
  rescue => e
    raise CloudflareError, "Erro ao conectar com API Cloudflare: #{e.message}"
  end
end