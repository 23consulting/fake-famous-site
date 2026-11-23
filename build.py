import base64,sys
s=open('index.src.html').read()
v=base64.b64encode(open('assets/hero.mp4','rb').read()).decode()
p=base64.b64encode(open('assets/hero-poster.jpg','rb').read()).decode()
s=s.replace('poster="assets/hero-poster.jpg"','poster="data:image/jpeg;base64,'+p+'"')
s=s.replace('<source src="assets/hero.mp4" type="video/mp4">','<source src="data:video/mp4;base64,'+v+'" type="video/mp4">')
s=s.replace('Put your influencer clip at assets/hero.mp4','The influencer clip and poster are embedded in this file (source: index.src.html + assets/). Replace assets/hero.mp4')
open('index.html','w').write(s)
print(len(s)//1024,'KB')
