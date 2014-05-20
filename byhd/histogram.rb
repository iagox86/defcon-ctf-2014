data = File.new(ARGV[0]).read

histogram = {}
data.each_byte() do |b|
  histogram[b.chr] = histogram[b.chr].nil?() ? 1 : histogram[b.chr] + 1
end
puts(histogram)
