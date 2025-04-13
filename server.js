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
DB.connectDB();

// Lire le fichier sample-cve.json
const sampleCvePath = path.join(__dirname, 'examples', 'sample-cve.json');

try {
    // Lire et parser le fichier JSON
    const cveData = JSON.parse(fs.readFileSync(sampleCvePath, 'utf8'));
    console.log('Fichier CVE lu avec succès');

    // Insérer le CVE dans la base de données
    cveService.insertCve(cveData)
        .then(async result => {
            const affectedProducts = result.getAffectedProducts();

            try {
                const savedProducts = await extractAndSaveProducts(result);

                // Afficher les détails des produits sauvegardés
                if (savedProducts.length > 0) {
                    savedProducts.forEach(product => {
                        console.log(`- ${product.vendor}/${product.product}`);

                        // Afficher les versions
                        if (product.versions && product.versions.length) {
                            product.versions.forEach(version => {
                                let versionInfo = `    * ${version.version} (${version.status})`;
                                if (version.lessThanOrEqual) {
                                    versionInfo += ` <= ${version.lessThanOrEqual}`;
                                } else if (version.lessThan) {
                                    versionInfo += ` < ${version.lessThan}`;
                                }
                            });
                        }
                    });
                }
            } catch (error) {
                console.error('Erreur lors de l\'extraction des produits:', error.message);
            }

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