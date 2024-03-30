require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # Producthunt oauth2 strategy
    class Producthunt < ::OmniAuth::Strategies::OAuth2
      option :name, 'producthunt'

      option :client_options,
             site: 'https://api.producthunt.com/v2/api',
             authorize_url: 'https://api.producthunt.com/v2/oauth/authorize',
             token_url: 'https://api.producthunt.com/v2/oauth/token'

      uid {
        raw_info['user']['id']
      }

      info do
        user_info = raw_info['user']
        {
          name: user_info['name'],
          email: nil,
          nickname: user_info['username'],
          image: user_info['profileImage'],
          twitter_username: user_info['twitterUsername']
        }
      end

      extra do
        { 'raw_info' => raw_info }
      end

      def authorize_params
        super.tap { |p| p[:scope] = 'public private' }
      end

      def callback_url
        # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
        options[:callback_url] || (full_host + script_name + callback_path)
      end

      def raw_info
        # graphql query to get user information
        request_body = {
          body: {
            query: "query { viewer { user { id name username profileImage twitterUsername } } }"
          }
        }
        @raw_info ||= access_token.post('graphql', request_body).parsed.dig('data', 'viewer')
      end
    end
  end
end
