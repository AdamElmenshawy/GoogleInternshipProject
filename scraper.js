const axios = require('axios');
const cheerio = require('cheerio');

const url = 'https://source.android.com/docs/security/bulletin/2024-10-01';

axios.get(url)
  .then(response => {
    const $ = cheerio.load(response.data);

    const cveDetails = [];

    // Locate the table containing the CVE entries. Adjust the selector based on the actual HTML.
    $('table').each((index, table) => {
      // Iterate through rows in the table
      $(table).find('tr').each((index, row) => {
        const cells = $(row).find('td');

        // Check if the row contains the necessary number of columns (for CVE details)
        if (cells.length >= 5) {
          const cveId = $(cells[0]).text().trim();  // CVE ID (e.g., CVE-2024-40673)
          const reference = $(cells[1]).text().trim();  // Reference (e.g., A-309938635)
          const type = $(cells[2]).text().trim();  // Type (e.g., RCE)
          const severity = $(cells[3]).text().trim();  // Severity (e.g., High)
          const versions = $(cells[4]).text().trim();  // Updated AOSP Versions (e.g., 12, 12L, 13, 14)

          // Create a structured CVE entry object
          if (cveId && reference && type && severity && versions) {
            cveDetails.push({
              bulletin: '2024-10-01',  // Hardcoded bulletin date for this example
              cve: cveId,
              reference: reference,
              type: type,
              severity: severity,
              updated_versions: versions.split(',').map(v => v.trim()),  // Split by commas and trim any extra spaces
              link: `${url}#${cveId.replace('CVE-', '').replace('.', '-')}`,  // Link to specific CVE entry
              patch_description: 'Description not extracted in this example',  // Placeholder for patch description
            });
          }
        }
      });
    });

    // Format the extracted data into the required structure
    const data = {
      version: 1,
      content: cveDetails
    };

    // Log the JSON output for the CVE details
    console.log('CVE Details:', JSON.stringify(data, null, 2));
  })
  .catch(error => {
    console.error('Error fetching the website:', error);
  });
