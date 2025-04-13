import { processCveFile, CveParser } from '../src/index.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs-extra';

// Obtenir le chemin du répertoire actuel
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Exemple 1: Utilisation de la fonction utilitaire rapide
async function example1() {
    console.log('=== Exemple 1: Utilisation de la fonction utilitaire processCveFile ===');

    try {
        const samplePath = path.join(__dirname, 'sample-cve.json');

        if (!fs.existsSync(samplePath)) {
            console.error(`Le fichier exemple ${samplePath} n'existe pas. Veuillez créer un fichier CVE d'exemple.`);
            return;
        }

        const { cveObject, validationResult } = await processCveFile(samplePath);

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
        refs.slice(0, 3).forEach((ref, i) => {
            console.log(`  ${i+1}. ${ref.url}`);
        });

        console.log('\nValidation:', validationResult.valid ? 'Succès' : 'Échec');
        if (!validationResult.valid) {
            console.log(`  ${validationResult.errors.length} erreurs trouvées`);
            // Afficher les 3 premières erreurs pour un aperçu
            validationResult.errors.slice(0, 3).forEach((err, i) => {
                console.log(`  - Erreur ${i+1}: ${err.instancePath} ${err.message}`);
            });
        }
    } catch (error) {
        console.error('Erreur dans l\'exemple 1:', error.message);
    }
}

// Exemple 2: Utilisation manuelle de la classe CveParser avec plus de contrôle
async function example2() {
    console.log('\n=== Exemple 2: Utilisation manuelle de la classe CveParser ===');

    try {
        const parser = new CveParser();
        const samplePath = path.join(__dirname, 'sample-cve.json');

        if (!fs.existsSync(samplePath)) {
            console.error(`Le fichier exemple ${samplePath} n'existe pas. Veuillez créer un fichier CVE d'exemple.`);
            return;
        }

        // Chargement du fichier CVE
        const cveData = await parser.loadCveFromFile(samplePath);
        console.log('Fichier CVE chargé avec succès');

        // Validation manuelle
        const validationResult = await parser.validateCve(cveData);
        console.log('Validation:', validationResult.valid ? 'Succès' : 'Échec');

        // Construction de l'objet
        const cveObject = parser.buildCveObject(cveData);
        console.log(`\nCVE ID: ${cveObject.getCveId()}`);

        // Accès aux données brutes
        console.log('\nAccès aux données brutes:');
        const rawData = cveObject.getRawData();
        console.log(`  Type de données: ${rawData.dataType}`);
        console.log(`  Version des données: ${rawData.dataVersion}`);

        // Conversion en JSON pour stockage/transmission
        const jsonString = cveObject.toJSON();
        console.log(`\nLongueur de la chaîne JSON: ${jsonString.length} caractères`);
    } catch (error) {
        console.error('Erreur dans l\'exemple 2:', error.message);
    }
}

// Exécuter les exemples
async function runExamples() {
    try {
        await example1();
        await example2();
    } catch (error) {
        console.error('Erreur lors de l\'exécution des exemples:', error);
    }
}

runExamples();