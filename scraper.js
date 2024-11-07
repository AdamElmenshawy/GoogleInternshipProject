const axios = require('axios');
const cheerio = require('cheerio');

// Step 1: Define the URL to scrape
const url = 'const axios = require('axios');
const cheerio = require('cheerio');

// Step 1: Define the URL to scrape
const url = 'https://example.com'; // Replace with the target website

// Step 2: Fetch the website content
axios.get(url)
  .then(response => {
    // Step 3: Load the response data into Cheerio
    const $ = cheerio.load(response.data);

    // Step 4: Extract the desired data
    // Example: Get all headings (h1, h2, h3)
    const headings = [];
    $('h1, h2, h3').each((index, element) => {
      headings.push($(element).text());
    });

    console.log('Headings:', headings);

    // Example: Get all paragraphs
    const paragraphs = [];
    $('p').each((index, element) => {
      paragraphs.push($(element).text());
    });

    console.log('Paragraphs:', paragraphs);

    // Example: Get all links (URLs and their text)
    const links = [];
    $('a').each((index, element) => {
      const link = $(element).attr('href');
      const text = $(element).text();
      links.push({ text, link });
    });

    console.log('Links:', links);
  })
  .catch(error => {
    console.error('Error fetching the website:', error);
  });
// Replace with the target website

// Step 2: Fetch the website content
axios.get(url)
  .then(response => {
    // Step 3: Load the response data into Cheerio
    const $ = cheerio.load(response.data);

    // Step 4: Extract the desired data
    // Example: Get all headings (h1, h2, h3)
    const headings = [];
    $('h1, h2, h3').each((index, element) => {
      headings.push($(element).text());
    });

    console.log('Headings:', headings);

    // Example: Get all paragraphs
    const paragraphs = [];
    $('p').each((index, element) => {
      paragraphs.push($(element).text());
    });

    console.log('Paragraphs:', paragraphs);

    // Example: Get all links (URLs and their text)
    const links = [];
    $('a').each((index, element) => {
      const link = $(element).attr('href');
      const text = $(element).text();
      links.push({ text, link });
    });

    console.log('Links:', links);
  })
  .catch(error => {
    console.error('Error fetching the website:', error);
  });
