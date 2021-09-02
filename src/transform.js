const fs = require('fs');

let usuarios = require("./jsonimport.json")
let final = []
for (i in usuarios.alumnos) {
    usuarios.alumnos[i].tipo = "Alumno"
    final.push(usuarios.alumnos[i])
}
for (i in usuarios.apoderados) {
    usuarios.apoderados[i].tipo = "Apoderado"
    final.push(usuarios.apoderados[i])
}
for (i in usuarios.trabajadores) {
    usuarios.trabajadores[i].tipo = "Trabajador"
    final.push(usuarios.trabajadores[i])
}
let data = JSON.stringify(final, null, 2);


fs.writeFile('jsonparse.json', data, (err) => {
    if (err) throw err;
    console.log('Data written to file');
});