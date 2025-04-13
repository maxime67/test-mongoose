import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import DB from './config/db.js';
import cveService from './services/cveService.js';

// Obtenir le chemin du répertoire actuel en mode ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Connexion à MongoDB
DB.connectDB();

// Lire le fichier sample-cve.json
const sampleCvePath = path.join(__dirname, 'examples', 'sample-cve.json');

try {
    // Lire et parser le fichier JSON
    const cveData = JSON.parse(fs.readFileSync(sampleCvePath, 'utf8'));
    console.log('Fichier CVE lu avec succès');

    // Insérer le CVE dans la base de données
    cveService.insertCve(cveData)
        .then(result => {
            console.log('CVE inséré avec succès:', result.cveMetadata.cveId);
            console.log('Titre:', result.getTitle());
            console.log('Description:', result.getDescription());

            // Afficher les produits affectés
            const affectedProducts = result.getAffectedProducts();
            console.log(`Nombre de produits affectés: ${affectedProducts.length}`);
            affectedProducts.forEach(product => {
                console.log(product)
            });
        })
        .catch(error => {
            console.error('Erreur lors de l\'insertion du CVE:', error.message);
        })
        .finally(() => {
            // Attendre un peu avant de fermer la connexion pour laisser le temps à Mongoose de terminer
            setTimeout(() => {
                console.log('Fermeture de la connexion à MongoDB');
                process.exit(0);
            }, 2000);
        });
} catch (error) {
    console.error('Erreur lors de la lecture du fichier CVE:', error.message);
    process.exit(1);
}