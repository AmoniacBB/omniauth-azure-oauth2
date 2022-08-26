require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'
      BASE_SCOPE_URL = 'https://graph.microsoft.com/'
      BASE_SCOPES = %w[profile email openid].freeze
      DEFAULT_SCOPE = 'email,profile'

      option :name, 'azure_oauth2'

      option :tenant_provider, nil
      option :pkce, true

      # tenant_provider must return client_id, client_secret and optionally tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.client_id
        options.client_secret = provider.client_secret
        options.tenant_id =
          provider.respond_to?(:tenant_id) ? provider.tenant_id : 'common'
        options.base_azure_url =
          provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL

        options.authorize_params = provider.authorize_params if provider.respond_to?(:authorize_params)
        options.authorize_params.domain_hint = provider.domain_hint if provider.respond_to?(:domain_hint) && provider.domain_hint
        if defined?(request)
          options.tenant_id = request.params['tenant_id'] if request.params['tenant_id']
          options.authorize_params.prompt = request.params['prompt'] if request.params['prompt']
        end
        options.client_options.authorize_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/authorize"
        options.client_options.token_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/v2.0/token"
        super
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end
          params[:response_mode] = 'form_post'
          params[:scope] = get_scope(params)
          params[:state] = request.params['state'] if defined?(request) && request.params['state']
          session['omniauth.state'] = params[:state] if params[:state]
        end
      end

      def token_params
        binding.pry
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid']
        }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token.token, nil, false).first
      end

      private

      def get_scope(params)
        raw_scope = params[:scope] || DEFAULT_SCOPE
        scope_list = raw_scope.split(' ').map { |item| item.split(',') }.flatten
        scope_list.map! { |s| s =~ %r{^https?://} || BASE_SCOPES.include?(s) ? s : "#{BASE_SCOPE_URL}#{s}" }
        scope_list.join(' ')
      end
    end
  end
end
