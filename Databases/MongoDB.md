
No SQL Database
Can contains multiple databases
Each database contains **collections** whiches are table in SQL databases

## Start db

```bash
sudo mongod --dbpath=/mongodata/
```

```bash
sudo systemctl start mongod
```
## Import database

```bash
mongoimport --db seed --collection pokemon --file seed.json --jsonArray
```

## List databases

```mongosh
show dbs         # displays dbs
use DB_NAME      # select a db to use
show collections # db need to be selected
```


## CheatSheet

Note : pokemon is the collection name

**Find all**
```mongodb
db.pokemon.find({})
```


**STEP 1** - Print all the Pokemon names to the MongoDB console like so `name: <name_of_pokemon>`.  
```json
db.pokemon.find({},{name:1})
```

**STEP 2** - Find the Pokemon with the name "Mew".  
```json
db.pokemon.find({name:"Mew"})
```

**STEP 3** - How many Pokemons are 87.5 male?  
```json
db.pokemon.findOne({ "misc.sex.male": 87.5 });
```

**STEP 4** - How many Pokemons have `ice : "2"`?  
```json
db.pokemon.find({ "damages.ice":"2" }).count();
```

**STEP 5** - How many Pokemons have `ice : "2"` AND `female : "12.5"`?  
```json
db.pokemon.find({ "damages.ice":"2", "misc.sex.male": 87.5 }).count()
```

**STEP 6** - How many Pokemons have `"speed": "60"` OR `"type" : "Grass"`?  
```json
db.pokemon.find({ $or: [{"stats.speed":"60"}, {"type": "Grass"}] }).count()
```

**STEP 7** - How many have BOTH `"speed": "60"` AND `"type" : "Grass"`?
```json
db.pokemon.find({ $and: [{"stats.speed":"60"}, {"type": "Grass"}]} ).count()
```

**STEP 8** - Create a new collection named `Schmittymons` and add a new `Schmittymon` with the following traits:

- **name**: Schmitty
- **img**: [http://40.media.tumblr.com/tumblr_m78kl3JexC1rag2cto1_500.jpg](http://40.media.tumblr.com/tumblr_m78kl3JexC1rag2cto1_500.jpg)
- **tutor**:
    - **name**: grass pledge
    - **gen**: V
- **happiness**: 99

```json
db.Schmittymons.insertOne({
    name: "Schmitty",
    img: "http://40.media.tumblr.com/tumblr_m78kl3JexC1rag2cto1_500.jpg",
    tutor: {
        name: "grass pledge",
        gen: "V"
    },
    happiness: 99
});
```


## 3- Sauvegarde : import, export et dump binaire
- Créez une nouvelle base de donnée sur la thématique des meubles
```json
use meubles
```

```json
db.meubles.insertMany([
    {
        name: "Table à manger en bois",
        type: "Table",
        material: "Bois",
        color: "Brun",
        dimensions: {
            length: 160,
            width: 90,
            height: 75
        },
        price: 300
    },
    {
        name: "Canapé d'angle en cuir",
        type: "Canapé",
        material: "Cuir",
        color: "Noir",
        dimensions: {
            length: 250,
            width: 200,
            height: 80
        },
        price: 800
    },
    {
        name: "Lit double avec tête de lit rembourrée",
        type: "Lit",
        material: "Bois",
        color: "Blanc",
        dimensions: {
            length: 200,
            width: 160,
            height: 100
        },
        price: 600
    },
    // Ajoutez autant d'objets que nécessaire
]);

```

- Exportez votre base dans un fichier texte
```bash
mongoexport --db meubles --collection meubles --out export_text.txt
```

- Exportez votre base dans un fichier binaire
```bash
mongodump --db meubles --out dump_folder
```

- Stoppez le serveur mongod
```
CTRL+C
```

- Créez un nouveau dossier de données et relancez mongod en utilisant ce dossier
```bash
mkdir new_data_folder
mongod --dbpath ./new_data_folder
```

- Importez votre base depuis le fichier texte
```bash
mongoimport --db meubles --collection meubles --file export_text.txt
```

- Vérifiez le bon fonctionnement de l’import
```json
mongosh
use meubles
db.meubles.find()
```

- Supprimez la base
```json
use meubles
db.dropDatabase()
```

- Réimportez la base depuis le fichier binaire
```bash
mongorestore --db meubles dump_folder/meubles
```

- Vérifiez le bon fonctionnement de l’import
```json
mongosh
use meubles
db.meubles.find()
```
