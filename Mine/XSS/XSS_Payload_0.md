Search for these keywords which are responsible for injection
	innerHTML
	location.search
	location.search
	document.write

Use Burp Suite Interceptor to escape browser/html/js formatter(email,links,)
Check returnPath is reflected on any link such as (back, return to previous page)
	eg:
	https://www.asdff.com/returnPath=/
	https://www.asdff.com/returnPath=/post/comments

	<a href="/">Back</a>
	<a href="/post/comments">Back</a>

Check if input string is put into href attribute
	javascript:alert(1)
	
Check if input string gets responded within quoted attribute
	"onmouseover="alert(1)
	" onfocus=alert(1) autofocus
