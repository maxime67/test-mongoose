import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import DB from './config/db.js';
import cveService from './services/cveService.js';
import extractAndSaveProducts from './services/productExctactor.js';
import githubApiService from './services/githubApiService.js';

// Get current directory path in ES modules mode
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Global counters for tracking progress
let processedCount = 0;
let successCount = 0;
let errorCount = 0;

// Define the path to the folder containing CVE files
const cvesFolderPath = path.join(__dirname, 'examples/cves/');

async function main() {
    try {
        // // Synchronize CVE files from GitHub API
        // console.log('Synchronizing CVEs from GitHub...');
        // try {
        //     await githubApiService.sync();
        //     console.log('CVE synchronization completed.');
        // } catch (error) {
        //     console.error('Error during CVE synchronization:', error.message);
        //     console.log('Continuing process with existing files...');
        // }

        // Connect to MongoDB
        await DB.connectDB();

        // Create folder if it doesn't exist
        if (!fs.existsSync(cvesFolderPath)) {
            console.log(`Folder ${cvesFolderPath} doesn't exist, creating it...`);
            fs.mkdirSync(cvesFolderPath, { recursive: true });

            // Copy sample-cve.json to the new folder to have at least one example
            const samplePath = path.join(__dirname, 'examples', 'sample-cve.json');
            if (fs.existsSync(samplePath)) {
                const destinationPath = path.join(cvesFolderPath, 'sample-cve.json');
                fs.copyFileSync(samplePath, destinationPath);
                console.log(`Example file copied to ${destinationPath}`);
            }
        }

        // Process all CVE folders and files
        await processAllCveFiles();

        // Display summary
        console.log('\nProcessing Summary:');
        console.log(`Total files processed: ${processedCount}`);
        console.log(`Success: ${successCount}`);
        console.log(`Errors: ${errorCount}`);

        // Close MongoDB connection after processing
        console.log('Closing MongoDB connection');
        setTimeout(() => {
            process.exit(0);
        }, 2000);
    } catch (error) {
        console.error('Unexpected error:', error);
        process.exit(1);
    }
}

async function processAllCveFiles() {
    try {
        // Read all items in the cvesFolderPath directory
        const items = fs.readdirSync(cvesFolderPath);

        // Filter out only the folders
        const folders = items.filter(item => {
            const itemPath = path.join(cvesFolderPath, item);
            return fs.statSync(itemPath).isDirectory();
        });

        console.log('Processing folders in', cvesFolderPath, ':');

        // If there are no folders, try to process JSON files directly in the main directory
        if (folders.length === 0) {
            const files = fs.readdirSync(cvesFolderPath);
            const jsonFiles = files.filter(file => file.endsWith('.json'));
            if (jsonFiles.length > 0) {
                console.log(`Found ${jsonFiles.length} JSON files in the main directory.`);
                await processJsonFiles(cvesFolderPath, jsonFiles);
            } else {
                console.log('No JSON files found.');
            }
            return;
        }

        // Process each folder
        for (const folder of folders) {
            const folderPath = path.join(cvesFolderPath, folder);
            const files = fs.readdirSync(folderPath);
            const jsonFiles = files.filter(file => file.endsWith('.json'));

            if (jsonFiles.length > 0) {
                console.log(`Processing folder ${folder}: ${jsonFiles.length} JSON files found.`);
                await processJsonFiles(folderPath, jsonFiles);
            }
        }
    } catch (error) {
        console.error(`Error reading directory ${cvesFolderPath}:`, error);
    }
}

async function processJsonFiles(folderPath, jsonFiles) {
    for (const jsonFile of jsonFiles) {
        const filePath = path.join(folderPath, jsonFile);
        console.log(`Processing file: ${jsonFile}`);

        try {
            // Read and parse the JSON file
            const cveData = JSON.parse(fs.readFileSync(filePath, 'utf8'));

            // Insert the CVE into the database
            const result = await cveService.insertCve(cveData);

            // Extract affected products
            const savedProducts = await extractAndSaveProducts(result);

            // Display details of saved products
            if (savedProducts.length > 0) {
                console.log(`Affected products for ${jsonFile}:`);
                savedProducts.forEach(product => {
                    console.log(`- ${product.vendor}/${product.product}`);
                });
            }

            successCount++;
            console.log(`File ${jsonFile} processed successfully.`);
        } catch (error) {
            errorCount++;
            console.error(`Error processing file ${jsonFile}:`, error.message);
        }

        processedCount++;
    }
}

// Start the main process
main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});