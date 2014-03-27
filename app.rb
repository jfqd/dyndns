# encoding: UTF-8
require 'rubygems'
require 'sinatra'
require 'active_record'

domain_regex = /(^$)|(^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(([0-9]{1,5})?\/.*)?$)/ix

YAML::load(File.open('config/database.yml'))['production'].symbolize_keys.each do |key, value|
  set key, value
end
 
ActiveRecord::Base.establish_connection(
  adapter: "mysql2",
  host:     settings.db_host,
  database: settings.db_name,
  username: settings.db_username,
  password: settings.db_password
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
    halt 403 if params[:token].blank? || params[:domain].blank?
    halt 403 if !params[:domain].match(domain_regex)
    t = AuthToken.find_by_token(params[:token])
    halt 403 if t.nil? # authorized user?
    u = User.find(t.user_id)
    halt 403 if u.nil? || u.state != 'active' # active user?
    r = Record.find_by_name(params[:domain])
    halt 403 if r.nil? || r.user_id != u.id # authorized for this domain?
    r.content = request.ip
    halt 400 if !r.save # updated?
    status 200
  rescue Exception => e
    halt 400
  end
end

get "/*" do
  halt 403
end
