import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import https from 'https';

// Configuration pour le service de synchronisation GitHub
const config = {
    // Chemin de l'API GitHub pour accéder au contenu du dossier
    apiPath: '/repos/CVEProject/cvelistV5/contents/cves/2025',
    // Nom d'hôte de l'API GitHub
    apiHost: 'api.github.com',
    // Dossier de destination pour les fichiers CVE
    destDir: './examples/cves',
    // User-Agent pour les requêtes API GitHub (obligatoire)
    userAgent: 'CVE-Sync-Tool'
};

// Obtenir le chemin du répertoire actuel en mode ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Chemin absolu du dossier de destination
const destDirPath = path.resolve(__dirname, '..', config.destDir);
// Chemin vers le fichier qui stocke l'état de la dernière synchronisation
const syncStatePath = path.resolve(__dirname, '..', '.sync-state.json');

/**
 * Service pour synchroniser les fichiers CVE depuis l'API GitHub
 */
const githubApiService = {
    /**
     * Initialise les dossiers nécessaires
     */
    async init() {
        // Créer le dossier de destination s'il n'existe pas
        await fs.ensureDir(destDirPath);

        // Initialiser l'état de synchronisation s'il n'existe pas
        if (!await fs.pathExists(syncStatePath)) {
            await fs.writeJson(syncStatePath, {
                lastSync: null,
                lastCommit: null
            });
        }
    },

    /**
     * Récupère l'état de la dernière synchronisation
     * @returns {Promise<Object>} État de la dernière synchronisation
     */
    async getSyncState() {
        try {
            return await fs.readJson(syncStatePath);
        } catch (error) {
            return { lastSync: null, lastCommit: null };
        }
    },

    /**
     * Met à jour l'état de synchronisation
     * @param {Object} state - Nouvel état de synchronisation
     */
    async updateSyncState(state) {
        await fs.writeJson(syncStatePath, state);
    },

    /**
     * Effectue une requête HTTPS à l'API GitHub
     * @param {string} path - Chemin de l'API
     * @returns {Promise<Object>} Réponse JSON de l'API
     */
    fetchFromGithub(path) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: config.apiHost,
                path: path,
                method: 'GET',
                headers: {
                    'User-Agent': config.userAgent,
                    'Accept': 'application/vnd.github.v3+json'
                }
            };

            const req = https.request(options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        try {
                            const jsonData = JSON.parse(data);
                            resolve(jsonData);
                        } catch (e) {
                            reject(new Error(`Erreur de parsing JSON: ${e.message}`));
                        }
                    } else {
                        reject(new Error(`Statut HTTP: ${res.statusCode}, Réponse: ${data}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.end();
        });
    },

    /**
     * Télécharge un fichier depuis une URL
     * @param {string} url - URL du fichier à télécharger
     * @returns {Promise<string>} Contenu du fichier
     */
    downloadFile(url) {
        return new Promise((resolve, reject) => {
            https.get(url, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(data);
                    } else {
                        reject(new Error(`Statut HTTP: ${res.statusCode}`));
                    }
                });
            }).on('error', (error) => {
                reject(error);
            });
        });
    },

    /**
     * Récupère la liste des fichiers dans un répertoire GitHub
     * @param {string} dirPath - Chemin du répertoire à explorer
     * @returns {Promise<Array>} Liste des éléments du répertoire
     */
    async listDirectory(dirPath) {
        try {
            return await this.fetchFromGithub(dirPath);
        } catch (error) {
            console.error(`Erreur lors de la liste du répertoire ${dirPath}:`, error.message);
            return [];
        }
    },

    /**
     * Récupère récursivement tous les fichiers .json d'un répertoire GitHub
     * @param {string} dirPath - Chemin du répertoire à explorer
     * @returns {Promise<Array>} Liste des fichiers .json
     */
    async getJsonFiles(dirPath) {
        const contents = await this.listDirectory(dirPath);
        const result = [];

        for (const item of contents) {
            if (item.type === 'file' && item.name.endsWith('.json')) {
                result.push(item);
            } else if (item.type === 'dir') {
                // Explorer récursivement les sous-répertoires
                const subDirFiles = await this.getJsonFiles(item.url.replace('https://api.github.com', ''));
                result.push(...subDirFiles);
            }
        }

        return result;
    },

    /**
     * Télécharge et sauvegarde les fichiers CVE
     */
    async downloadAndSaveFiles() {
        console.log('Récupération de la liste des fichiers CVE...');
        const files = await this.getJsonFiles(config.apiPath);

        console.log(`${files.length} fichiers CVE trouvés.`);
        let downloadCount = 0;

        for (const file of files) {
            try {
                // console.log(`Téléchargement de ${file.name}...`);
                const content = await this.downloadFile(file.download_url);

                // Déterminer le chemin de destination
                // Si le fichier est dans un sous-dossier, recréer la structure de dossiers
                const relativePath = file.path.replace('cves/2025/', '');
                const destPath = path.join(destDirPath, relativePath);

                // Créer le dossier parent si nécessaire
                await fs.ensureDir(path.dirname(destPath));

                // Sauvegarder le fichier
                await fs.writeFile(destPath, content);
                downloadCount++;
            } catch (error) {
                console.error(`Erreur lors du téléchargement de ${file.name}:`, error.message);
            }
        }

        console.log(`${downloadCount} fichiers CVE téléchargés avec succès.`);
        return downloadCount;
    },

    /**
     * Exécute la synchronisation complète
     */
    async sync() {
        try {
            console.log('Démarrage de la synchronisation des fichiers CVE via l\'API GitHub...');

            // Initialiser les dossiers et l'état
            await this.init();

            // Récupérer l'état de la dernière synchronisation
            const syncState = await this.getSyncState();

            // Obtenir les informations du dernier commit
            try {
                const repoInfo = await this.fetchFromGithub('/repos/CVEProject/cvelistV5/commits/main');
                const latestCommit = repoInfo.sha;

                // Vérifier si une synchronisation est nécessaire
                if (syncState.lastCommit === latestCommit) {
                    console.log('Aucune mise à jour nécessaire. Les fichiers sont déjà à jour.');
                    return false;
                }

                // Télécharger et sauvegarder les fichiers
                await this.downloadAndSaveFiles();

                // Mettre à jour l'état de synchronisation
                await this.updateSyncState({
                    lastSync: new Date().toISOString(),
                    lastCommit: latestCommit
                });

                console.log(`Synchronisation terminée avec succès. Dernier commit: ${latestCommit}`);
                return true;

            } catch (error) {
                // En cas d'erreur lors de la récupération du commit, forcer la synchronisation
                console.warn('Impossible de vérifier le dernier commit, synchronisation forcée...');
                await this.downloadAndSaveFiles();

                // Mettre à jour l'état de synchronisation
                await this.updateSyncState({
                    lastSync: new Date().toISOString(),
                    lastCommit: `api-sync-${Date.now()}`
                });

                console.log('Synchronisation terminée avec succès (mode forcé).');
                return true;
            }
        } catch (error) {
            console.error('Erreur lors de la synchronisation:', error.message);
            throw error;
        }
    },

    /**
     * Nettoie les ressources temporaires
     */
    async cleanup() {
        // Rien à nettoyer pour cette implémentation
        return true;
    }
};

// Permettre l'exécution directe du script
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    (async () => {
        try {
            await githubApiService.sync();
            process.exit(0);
        } catch (error) {
            console.error('Erreur lors de la synchronisation:', error);
            process.exit(1);
        }
    })();
}

export default githubApiService;