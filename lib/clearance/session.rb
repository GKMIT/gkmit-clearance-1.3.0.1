require 'clearance/default_sign_in_guard'

module Clearance
  class Session
    REMEMBER_TOKEN_COOKIE = 'remember_token'.freeze

    def initialize(env)
      @env = env
    end

    def add_cookie_to_headers(headers)
      Rack::Utils.set_cookie_header!(headers, REMEMBER_TOKEN_COOKIE, cookie_value)
    end

    def current_user
      if remember_token.present?
        @current_user ||= user_client_from_remember_token(remember_token)
        p "*******current user ******"
        p @current_user
      end
      @current_user
    end

    def sign_in(user,device_type, &block)
      @current_user = user
      status = run_sign_in_stack
      if status.success?
        cookies[REMEMBER_TOKEN_COOKIE] = user && user.remember_token(device_type)
      else
        @current_user = nil
      end
      if block_given?
        block.call(status)
      end
    end

    def sign_out
      if signed_in?
        current_user.reset_remember_token!
      end
      @current_user = nil unless UserClient.where(:user_id => current_user.id).count > 0
      cookies.delete REMEMBER_TOKEN_COOKIE
    end

    def signed_in?
      current_user.present?
    end

    def signed_out?
      ! signed_in?
    end

    private
    def cookies
      @cookies ||= @env['action_dispatch.cookies'] || Rack::Request.new(@env).cookies
    end

    def remember_token
      cookies[REMEMBER_TOKEN_COOKIE]
    end

    def remember_token_expires
      if expires_configuration.arity == 1
        expires_configuration.call(cookies)
      else
        warn "#{Kernel.caller.first}: [DEPRECATION] " +
          'Clearance.configuration.cookie_expiration lambda with no parameters ' +
          'has been deprecated and will be removed from a future release. The ' +
          'lambda should accept the collection of previously set cookies.'
        expires_configuration.call
      end
    end

    def expires_configuration
      Clearance.configuration.cookie_expiration
    end

    def user_from_remember_token(token)
      Clearance.configuration.user_model.where(remember_token: token).first
    end

    def user_client_from_remember_token(token)
      p "in user client from token"
      p token
      p "______________"
      p Clearance.configuration.user_client_model
      p "______________"
      p Clearance.configuration.user_model
      p "______________"
      p Clearance.configuration.user_client_model.where(remember_token: token).first
      p "______________"
      p Clearance.configuration.user_client_model.where(remember_token: token).first.user_id
      p "______________"
      # p Clearance.configuration.user_model.find(Clearance.configuration.user_client_model.where(remember_token: token).first.user_id)
      p "______________"
      p "______________"
      p "______________"
      p User.find((UserClient.where(remember_token: token).first).user_id) if UserClient.where(remember_token: token).first

      User.find((Clearance.configuration.user_client_model.where(remember_token: token).first).user_id) if Clearance.configuration.user_client_model.where(remember_token: token).first
    end

    def run_sign_in_stack
      @stack ||= initialize_sign_in_guard_stack
      @stack.call
    end

    def initialize_sign_in_guard_stack
      default_guard = DefaultSignInGuard.new(self)
      guards = Clearance.configuration.sign_in_guards

      guards.inject(default_guard) do |stack, guard_class|
        guard_class.new(self, stack)
      end
    end

    def cookie_value
      value = {
        expires: remember_token_expires,
        httponly: Clearance.configuration.httponly,
        path: Clearance.configuration.cookie_path,
        secure: Clearance.configuration.secure_cookie,
        value: remember_token
      }

      if Clearance.configuration.cookie_domain.present?
        value[:domain] = Clearance.configuration.cookie_domain
      end

      value
    end
  end
end
