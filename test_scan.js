// Simple test script to trigger a scan
import fetch from 'node-fetch';

async function testScan() {
    try {
        const response = await fetch('http://localhost:3000/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: 'https://httpbin.org/forms/post'
            })
        });
        
        const result = await response.json();
        console.log('Scan started:', result);
        
        // Wait a bit then check results
        setTimeout(async () => {
            try {
                const statusResponse = await fetch(`http://localhost:3000/api/scan/${result.scanId}`);
                const scanData = await statusResponse.json();
                console.log('Scan status:', scanData.status);
                console.log('Vulnerabilities found:', scanData.results?.vulnerabilities?.totalFound || 0);
                
                if (scanData.results?.vulnerabilities?.vulnerabilities) {
                    console.log('Vulnerability details:', scanData.results.vulnerabilities.vulnerabilities);
                }
            } catch (error) {
                console.error('Error checking scan:', error.message);
            }
        }, 10000); // Wait 10 seconds
        
    } catch (error) {
        console.error('Error starting scan:', error.message);
    }
}

testScan();