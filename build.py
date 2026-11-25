# Builds index.html from index.src.html.
# The hero clip and poster are served as normal files from assets/ (not embedded),
# so browsers can stream and autoplay the video. Replace assets/hero.mp4 and
# assets/hero-poster.jpg to change them.
s = open('index.src.html').read()
open('index.html', 'w').write(s)
print(len(s) // 1024, 'KB')
