# encoding: UTF-8
require 'rubygems'
require 'sinatra'
require 'active_record'
require 'yaml'
require 'ipaddr'
require 'dotenv/load'
require 'erb'

domain_regex = /(^$)|(^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(([0-9]{1,5})?\/.*)?$)/ix

YAML::load(File.open('config/database.yml'))['production'].each do |key, value|
  renderer = ERB.new(value)
  set key, renderer.result()
end

configure do
  # http://recipes.sinatrarb.com/p/middleware/rack_commonlogger
  file = File.new("#{settings.root}/log/#{settings.environment}.log", 'a+')
  file.sync = true
  use Rack::CommonLogger, file
end

ActiveRecord::Base.establish_connection(
  adapter:  settings.adapter,
  host:     settings.host,
  database: settings.database,
  username: settings.username,
  password: settings.password
)

class AuthToken < ActiveRecord::Base
  self.inheritance_column = :___disabled
end
class User < ActiveRecord::Base
  self.inheritance_column = :___disabled
end
class Record < ActiveRecord::Base
  self.inheritance_column = :___disabled
end

class String
  def blank?
    self == nil || self == ''
  end
end

get "/ip" do
  request.ip
end

get '/update/:token/:domain' do
  begin
    ActiveRecord::Base.clear_active_connections!
    halt 403 if params[:token].blank? || params[:domain].blank?
    halt 403 if !params[:domain].match(domain_regex)
    t = AuthToken.find_by_token(params[:token])
    halt 403 if t.nil? # authorized user?
    u = User.find(t.user_id)
    halt 403 if u.nil? || u.state != 'active' # active user?
    rt = IPAddr.new(request.ip).ipv6? ? "AAAA" : "A"
    r = Record.find_by_name_and_type(params[:domain],rt)
    halt 403 if r.nil? || r.user_id != u.id # authorized for this domain?
    r.content = request.ip
    if !r.save # updated?
      logger.warn "[DynDNS#update] Error: halt on save"
      halt 400
    end
    status 200
  rescue Exception => e
    logger.warn "[DynDNS#update] Rescue: #{e.message}"
    halt 400
  end
end

get "/robots.txt" do
  %{User-agent: *\nDisallow: /}
end

get '/ping' do
  'pong'
end

get "/*" do
  halt 403
end
