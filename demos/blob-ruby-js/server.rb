require 'sinatra'
require './opaque.so'

include Opaque

def bin_to_hex(s)
  s.unpack('H*').first
end

def hex_to_bin(s)
  s.scan(/../).map { |x| x.hex }.pack('c*')
end

set :public_folder, __dir__ + '/static'

get '/' do
  send_file File.join(settings.public_folder, 'index.html')
end

post '/request-creds' do
  request.body.rewind
  req = hex_to_bin(params['request'])
  rec = hex_to_bin("7a3c6282f02d37a05023b60d5428e6cc5961d4c31221937adae0b574e4d07205000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f8046ad706b646aa60db1e34399313dfe447af7065d3ef802ed8198beeb50033912cc4e58f95b7a54b4b3978a9ca29b8c06e298899de0622bb50ab6353c056a152864e882b72832e5978766b16d590d904f584e797c6781f095a8c241320f0be2000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe8fa434d3f4b0e6b6e7504dba82007ec2cadd271e64a570d5adb083a5eadcff3d26fe084b0e147a0f3aa74ea4b5b699981ff98500a45f50f8990cc8b18918491")
  blob = 'a273ecee9359b40b9d706d8b23badb018b75709970d97a9196dbd3c59324aac134b7a8006f935570cd0ae0a36358f06eebc076c3c55a9c1ee851831261774ce3'
  resp, _, _ = create_credential_response(req, rec, "demo user", "demo server", "rbopaque-v0.2.0-demo")
  content_type :json
  { response: bin_to_hex(resp), blob: blob }.to_json
end
