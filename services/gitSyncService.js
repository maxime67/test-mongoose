import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import simpleGit from 'simple-git';

// Configuration pour le service de synchronisation Git
const config = {
    // URL du dépôt GitHub à cloner
    repoUrl: 'https://github.com/CVEProject/cvelistV5.git',
    // Chemin relatif dans le dépôt vers les fichiers CVE de 2025
    sourcePath: 'cves/2025',
    // Dossier temporaire pour cloner le dépôt
    tempDir: './temp-cvelistV5',
    // Dossier de destination pour les fichiers CVE
    destDir: './examples/cves',
    // Option pour forcer une synchronisation complète (ignorer le dernier commit connu)
    forceSync: false
};

// Obtenir le chemin du répertoire actuel en mode ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Chemin absolu du dossier temporaire
const tempDirPath = path.resolve(__dirname, '..', config.tempDir);
// Chemin absolu du dossier de destination
const destDirPath = path.resolve(__dirname, '..', config.destDir);
// Chemin vers le fichier qui stocke l'état de la dernière synchronisation
const syncStatePath = path.resolve(__dirname, '..', '.sync-state.json');

/**
 * Service pour synchroniser les fichiers CVE depuis le dépôt GitHub
 */
const gitSyncService = {
    /**
     * Initialise les dossiers nécessaires
     */
    async init() {
        // Créer le dossier de destination s'il n'existe pas
        await fs.ensureDir(destDirPath);

        // Créer le dossier temporaire s'il n'existe pas
        await fs.ensureDir(tempDirPath);

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
     * Clone ou met à jour le dépôt distant
     * @returns {Promise<simpleGit.SimpleGit>} Instance Git
     */
    async cloneOrUpdateRepo() {
        const git = simpleGit();

        // Vérifier si le dépôt est déjà cloné
        const isRepo = await fs.pathExists(path.join(tempDirPath, '.git'));

        if (isRepo) {
            console.log('Mise à jour du dépôt existant...');
            // Aller dans le dossier du dépôt
            const repoGit = git.cwd(tempDirPath);
            // Récupérer les dernières modifications
            await repoGit.fetch(['--all']);
            await repoGit.reset(['--hard', 'origin/main']);
            await repoGit.pull('origin', 'main');
            return repoGit;
        } else {
            console.log('Clonage du dépôt...');
            // Supprimer le dossier s'il existe mais n'est pas un dépôt Git valide
            if (await fs.pathExists(tempDirPath)) {
                await fs.remove(tempDirPath);
            }
            // Cloner le dépôt
            await git.clone(config.repoUrl, tempDirPath, ['--depth=1']);
            return git.cwd(tempDirPath);
        }
    },

    /**
     * Copie les fichiers CVE de 2025 vers le dossier de destination
     */
    async copyFiles() {
        const sourceDirPath = path.join(tempDirPath, config.sourcePath);

        // Vérifier si le dossier source existe
        if (!await fs.pathExists(sourceDirPath)) {
            throw new Error(`Le dossier source ${sourceDirPath} n'existe pas`);
        }

        console.log(`Copie des fichiers depuis ${sourceDirPath} vers ${destDirPath}...`);

        // Liste récursive de tous les fichiers .json dans le dossier source
        const files = await fs.readdir(sourceDirPath, { withFileTypes: true });

        let copiedCount = 0;

        for (const file of files) {
            if (file.isFile() && file.name.endsWith('.json')) {
                const sourcePath = path.join(sourceDirPath, file.name);
                const destPath = path.join(destDirPath, file.name);

                // Copier le fichier
                await fs.copy(sourcePath, destPath, { overwrite: true });
                copiedCount++;
            } else if (file.isDirectory()) {
                // Récursivement copier les fichiers des sous-dossiers
                const subSourcePath = path.join(sourceDirPath, file.name);
                const subDestPath = path.join(destDirPath, file.name);

                // Créer le sous-dossier de destination s'il n'existe pas
                await fs.ensureDir(subDestPath);

                // Lister et copier tous les fichiers .json du sous-dossier
                const subFiles = await fs.readdir(subSourcePath, { withFileTypes: true });
                for (const subFile of subFiles) {
                    if (subFile.isFile() && subFile.name.endsWith('.json')) {
                        const subSourceFilePath = path.join(subSourcePath, subFile.name);
                        const subDestFilePath = path.join(subDestPath, subFile.name);

                        // Copier le fichier
                        await fs.copy(subSourceFilePath, subDestFilePath, { overwrite: true });
                        copiedCount++;
                    }
                }
            }
        }

        console.log(`${copiedCount} fichiers CVE copiés avec succès.`);
    },

    /**
     * Exécute la synchronisation complète
     */
    async sync() {
        try {
            console.log('Démarrage de la synchronisation des fichiers CVE...');

            // Initialiser les dossiers et l'état
            await this.init();

            // Récupérer l'état de la dernière synchronisation
            const syncState = await this.getSyncState();

            // Cloner ou mettre à jour le dépôt
            const git = await this.cloneOrUpdateRepo();

            // Obtenir le dernier commit
            const log = await git.log(['--max-count=1']);
            const latestCommit = log.latest.hash;

            // Vérifier si une synchronisation est nécessaire
            if (!config.forceSync && syncState.lastCommit === latestCommit) {
                console.log('Aucune mise à jour nécessaire. Le dépôt est déjà à jour.');
                return false;
            }

            // Copier les fichiers
            await this.copyFiles();

            // Mettre à jour l'état de synchronisation
            await this.updateSyncState({
                lastSync: new Date().toISOString(),
                lastCommit: latestCommit
            });

            console.log(`Synchronisation terminée avec succès. Dernier commit: ${latestCommit}`);
            return true;
        } catch (error) {
            console.error('Erreur lors de la synchronisation:', error.message);
            throw error;
        }
    },

    /**
     * Nettoie les ressources temporaires (dossier de clone)
     */
    async cleanup() {
        try {
            if (await fs.pathExists(tempDirPath)) {
                console.log('Nettoyage du dossier temporaire...');
                await fs.remove(tempDirPath);
            }
        } catch (error) {
            console.error('Erreur lors du nettoyage:', error.message);
        }
    }
};

// Permettre l'exécution directe du script
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    (async () => {
        try {
            await gitSyncService.sync();
            process.exit(0);
        } catch (error) {
            console.error('Erreur lors de la synchronisation:', error);
            process.exit(1);
        }
    })();
}

export default gitSyncService;