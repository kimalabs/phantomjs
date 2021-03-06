# Find pizza in Mountain View using Yelp

page = new WebPage()
url = 'http://lite.yelp.com/search?find_desc=pizza&find_loc=94040&find_submit=Search'

page.open url,
  (status) ->
    if status isnt 'success'
      console.log 'Unable to access network'
    else
      results = page.evaluate ->
        pizza = []
        list = document.querySelectorAll 'span.address'
        for item in list
          pizza.push(item.innerText)
        return pizza
      console.log results.join('\n')
    phantom.exit()
