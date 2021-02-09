# frozen_string_literal: true

require 'rubygems'
require 'bundler'
Bundler.require

require 'dotenv'
Dotenv.load

require 'sinatra'
require 'sinatra/reloader' if development?
require 'json'
require 'net/http'

TOKEN = ENV['TOKEN']
API_KEY = ENV['API_KEY']
CLIENT_ID = ENV['CLIENT_ID']

post '/url', provides: :json do
  params = JSON.parse(request.body.read)
  raise Sinatra::BadRequest if params['token'] != TOKEN

  uri = URI.parse('https://safebrowsing.googleapis.com/v4/threatMatches:find')

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  headers = {
    'Content-Type' => 'application/json'
  }

  body = {
    'client' => {
      'clientId' => CLIENT_ID,
      'clientVersion' => '0.0.1'
    },
    'threatInfo' => {
      'threatTypes' => %w[MALWARE SOCIAL_ENGINEERING UNWANTED_SOFTWARE POTENTIALLY_HARMFUL_APPLICATION],
      'platformTypes' => ['ALL_PLATFORMS'],
      'threatEntryTypes' => ['URL'],
      'threatEntries' => [
        { 'url' => params['url'].to_s }
      ]
    }
  }.to_json

  res = http.post(uri.path + "?key=#{API_KEY}", body, headers)
  raise 'API Error' if res.code[0] != '2'

  result = JSON.parse(res.body)
  threat_type = if result['matches']
                  result['matches'].first['threatType']
                else
                  'OK'
                end

  { "threatType" => threat_type }.to_json
end
