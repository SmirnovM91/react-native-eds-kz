require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-eds-kz"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-eds-kz
                   DESC
  s.homepage     = "https://github.com/SmirnovM91/react-native-eds-kz"
  # brief license entry:
  s.license      = "MIT"
  # optional - use expanded license entry instead:
  # s.license    = { :type => "MIT", :file => "LICENSE" }
  s.authors      = { "A|M Smirnov" => "smirnov.m.n.91@gmail.com" }
  s.platforms    = { :ios => "9.0" }
  s.source       = { :git => "https://github.com/SmirnovM91/react-native-eds-kz.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,c,m,swift}"
  s.requires_arc = true

  s.dependency "React"
  s.vendored_libraries = 'ios/libs/*.a'
  # s.pod_target_xcconfig = { 
  #   'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/../../node_modules/react-native-eds-kz/ios/libs/include"', 
  #   'LIBRARY_SEARCH_PATHS' => '"${PODS_ROOT}/../../node_modules/react-native-eds-kz/ios/libs"' 
  # }

end

