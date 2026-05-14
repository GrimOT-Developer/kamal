require "test_helper"

class Kamal::Configuration::Ssl::CloudflareTest < ActiveSupport::TestCase
  setup do
    @config = Kamal::Configuration.new(service: "app")
    @secrets = { "CF_API_TOKEN" => "test_token" }
    @cloudflare = Kamal::Configuration::Ssl::Cloudflare.new(@config, @secrets)
  end

  test "normalize domains includes apex when wildcard present" do
    domains = ["*.staging.cotaqui.com"]
    normalized = @cloudflare.send(:normalize_domains, domains)
    
    assert_includes normalized, "*.staging.cotaqui.com"
    assert_includes normalized, "staging.cotaqui.com"
  end

  test "normalize domains handles mixed apex and wildcard" do
    domains = ["staging.cotaqui.com", "*.staging.cotaqui.com", "api.staging.cotaqui.com"]
    normalized = @cloudflare.send(:normalize_domains, domains)
    
    expected = ["*.staging.cotaqui.com", "api.staging.cotaqui.com", "staging.cotaqui.com"]
    assert_equal expected, normalized
  end

  test "raises error when CF_API_TOKEN not found" do
    cloudflare = Kamal::Configuration::Ssl::Cloudflare.new(@config, {})
    
    assert_raises Kamal::Configuration::Ssl::Cloudflare::CloudflareError do
      cloudflare.send(:validate_prerequisites!)
    end
  end

  test "api_token prefers secrets over ENV" do
    ENV["CF_API_TOKEN"] = "env_token"
    
    assert_equal "test_token", @cloudflare.send(:api_token)
    
    ENV.delete("CF_API_TOKEN")
  end
end