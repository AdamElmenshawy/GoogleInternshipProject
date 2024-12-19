const axios = require('axios');
const cheerio = require('cheerio');

const url = 'https://source.android.com/docs/security/bulletin/2024-12-01'; 

axios.get(url)
  .then(response => {
    const $ = cheerio.load(response.data);
    console.log(response.data);

    // Initialize an object to store the data
    const securityData = [];

    // Loop through all affected components
    $('span.devsite-heading[role="heading"]').each((index, headingElement) => {
      const componentName = $(headingElement).text().trim();
      console.log(componentName);

      // Initialize an object for this component
      const componentData = {
        component: componentName,
        cves: []
      };

      // Find the table(s) containing CVEs for this component
      $(headingElement).nextUntil('span.devsite-heading').each((i, tableElement) => {
        if ($(tableElement).hasClass('devsite-table-wrapper')) {
          // Extract CVE details from the table
          const cveDetails = [];
          $(tableElement).find('tr').each((index, row) => {
            const cveId = $(row).find('td').eq(0).text().trim();
            const cveSeverity = $(row).find('td').eq(1).text().trim();
            const cveDescription = $(row).find('td').eq(2).text().trim();
            const affectedVersions = $(row).find('td').eq(3).text().trim();
            
            if (cveId) {
              cveDetails.push({
                cveId,
                severity: cveSeverity,
                description: cveDescription,
                affectedVersions
              });
            }
          });

          // Add the CVE details to the component data
          componentData.cves = componentData.cves.concat(cveDetails);
        }
      });

      // Add the component data to the securityData array
      if (componentData.cves.length > 0) {
        securityData.push(componentData);
      }
    });

    // Log the organized data
    console.log('Security Data:', JSON.stringify(securityData, null, 2));
  })
  .catch(error => {
    console.error('Error fetching the website:', error);
  });
