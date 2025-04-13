import { SimpleCveParser } from '../src/index.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs-extra';

// Obtenir le chemin du répertoire actuel
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runSimpleExample() {
    console.log('=== Exemple simple avec SimpleCveParser ===');

    try {
        const parser = new SimpleCveParser();
        const samplePath = path.join(__dirname, 'sample-cve.json');

        if (!fs.existsSync(samplePath)) {
            console.error(`Le fichier exemple ${samplePath} n'existe pas. Veuillez créer un fichier CVE d'exemple.`);
            return;
        }

        // Traiter le fichier CVE
        const { cveObject, validationResult } = await parser.processCveFile(samplePath);

        console.log(`\nCVE ID: ${cveObject.getCveId()}`);
        console.log(`Titre: ${cveObject.getTitle()}`);
        console.log(`Description: ${cveObject.getDescription()}`);
        console.log(`État: ${cveObject.getState()}`);
        console.log(`Date de publication: ${cveObject.getPublishedDate()}`);

        console.log('\nProduits affectés:');
        const products = cveObject.getAffectedProducts();
        products.forEach((product, i) => {
            console.log(`  ${i+1}. ${product.vendor || ''}${product.product ? ' ' + product.product : ''}`);
        });

        console.log('\nScores CVSS:');
        const scores = cveObject.getCvssScores();
        scores.forEach(score => {
            console.log(`  CVSS ${score.version}: ${score.baseScore} (${score.baseSeverity || ''})`);
        });

        console.log('\nRéférences:');
        const refs = cveObject.getReferences();
        refs.forEach((ref, i) => {
            console.log(`  ${i+1}. ${ref.url} (${ref.name || 'Sans nom'})`);
        });

        console.log('\nValidation:', validationResult.valid ? 'Succès' : 'Échec');
        if (!validationResult.valid) {
            console.log(`  ${validationResult.errors.length} erreurs trouvées`);
            validationResult.errors.forEach((err, i) => {
                console.log(`  - Erreur ${i+1}: ${err.message}`);
            });
        }
    } catch (error) {
        console.error('Erreur dans l\'exemple simple:', error);
    }
}

runSimpleExample();