import CveParser from './CveParser.js';
import CveValidator from './CveValidator.js';
import SimpleCveParser from './SimpleCveParser.js';
import * as utils from './utils.js';

/**
 * Point d'entrée principal pour le module CVE Parser
 */
export { CveParser, CveValidator, SimpleCveParser, utils };

// Export d'une fonction utilitaire pour traiter rapidement un fichier CVE
export async function processCveFile(filePath) {
    // Utiliser SimpleCveParser pour plus de fiabilité
    const parser = new SimpleCveParser();
    return parser.processCveFile(filePath);
}

// Exportation par défaut
export default {
    CveParser,
    CveValidator,
    SimpleCveParser,
    utils,
    processCveFile
};