const axios = require('axios');
const cheerio = require('cheerio');

const url = 'https://source.android.com/docs/security/bulletin/'; 

axios.get(url)
  .then(response => {
    const $ = cheerio.load(response.data);

//     const headings = [];
//     $('h1, h2, h3').each((index, element) => {
//       headings.push($(element).text());
//     });

//     console.log('Headings:', headings);

//     const paragraphs = [];
//     $('p').each((index, element) => {
//       paragraphs.push($(element).text());
//     });

//     console.log('Paragraphs:', paragraphs);

   
    const links = [];
    $('a').each((index, element) => {
      const link = $(element).attr('href');
      const text = $(element).text();
      if(link && link.startsWith("/docs/security/bulletin/")) {
        links.push({ text, link });
}
    });

    console.log('Links:', links);
  })
  .catch(error => {
    console.error('Error fetching the website:', error);
  });
