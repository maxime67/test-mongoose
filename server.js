import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import DB from './config/db.js';
import cveService from './services/cveService.js';
import extractAndSaveProducts from './services/productExctactor.js';

// Obtenir le chemin du répertoire actuel en mode ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Connexion à MongoDB
await DB.connectDB();

// Définir le chemin du dossier contenant les fichiers CVE
const cvesFolderPath = path.join(__dirname, 'examples', 'cves');

// Créer le dossier s'il n'existe pas
if (!fs.existsSync(cvesFolderPath)) {
    console.log(`Le dossier ${cvesFolderPath} n'existe pas, création en cours...`);
    fs.mkdirSync(cvesFolderPath, { recursive: true });

    // Déplacer sample-cve.json dans le nouveau dossier pour avoir au moins un exemple
    const samplePath = path.join(__dirname, 'examples', 'sample-cve.json');
    if (fs.existsSync(samplePath)) {
        const destinationPath = path.join(cvesFolderPath, 'sample-cve.json');
        fs.copyFileSync(samplePath, destinationPath);
        console.log(`Fichier exemple copié vers ${destinationPath}`);
    }
}

// Lire tous les fichiers du dossier
const files = fs.readdirSync(cvesFolderPath);
const jsonFiles = files.filter(file => file.endsWith('.json'));

console.log(`Nombre de fichiers JSON trouvés: ${jsonFiles.length}`);

// Variable pour compter les CVE traités
let processedCount = 0;
let successCount = 0;
let errorCount = 0;

// Traiter chaque fichier JSON
for (const jsonFile of jsonFiles) {
    const filePath = path.join(cvesFolderPath, jsonFile);
    console.log(`Traitement du fichier: ${jsonFile}`);

    try {
        // Lire et parser le fichier JSON
        const cveData = JSON.parse(fs.readFileSync(filePath, 'utf8'));

        // Insérer le CVE dans la base de données
        const result = await cveService.insertCve(cveData);

        // Extraire les produits affectés
        const savedProducts = await extractAndSaveProducts(result);

        // Afficher les détails des produits sauvegardés
        if (savedProducts.length > 0) {
            console.log(`Produits affectés pour ${jsonFile}:`);
            savedProducts.forEach(product => {
                console.log(`- ${product.vendor}/${product.product}`);
            });
        }

        successCount++;
        console.log(`Fichier ${jsonFile} traité avec succès.`);
    } catch (error) {
        errorCount++;
        console.error(`Erreur lors du traitement du fichier ${jsonFile}:`, error.message);
    }

    processedCount++;
}

// Afficher un résumé
console.log('\nRésumé du traitement:');
console.log(`Total de fichiers traités: ${processedCount}`);
console.log(`Succès: ${successCount}`);
console.log(`Erreurs: ${errorCount}`);

// Fermer la connexion à MongoDB après traitement
console.log('Fermeture de la connexion à MongoDB');
setTimeout(() => {
    process.exit(0);
}, 2000);