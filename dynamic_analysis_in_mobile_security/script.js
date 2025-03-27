Java.perform(function() {
    var targetClass = Java.use("com.ejemplo.app.MainActivity");

    targetClass.generateString.implementation = function(seed) {
        console.log("Interceptado generateString con seed:", seed);
        
        // Probar diferentes valores de semilla
        for (var i = 0; i < 1000; i++) {
            var result = this.generateString(i);
            console.log("Intentando seed:", i, "Resultado:", result);
            
            // Verificar si el resultado tiene formato de flag
            if (result.startsWith("Holberton{") && result.endsWith("}")) {
                console.log("¡FLAG ENCONTRADA!: ", result);
            }
        }
        return this.generateString(seed);
    };
});
