

$(document).ready(function(){

    setInterval(function() {
            $.ajax({
              "url": "/smart-power-network/auto",
              "type": "GET",
              "datatype": "json",
              success: function (response) { 
               // console.log(response)
               var instance = JSON.parse(response["numSerial"]);
              // console.log(instance);
               var fields = instance[0]["fields"]; 

            document.getElementById("powerR").innerHTML = fields["power_r"];  
            document.getElementById("ampR").innerHTML = fields["currents_r"];  
            document.getElementById("voltR").innerHTML = fields["voltage_r"];  
            document.getElementById("powerY").innerHTML = fields["power_y"];
            document.getElementById("ampY").innerHTML = fields["currents_y"];
            document.getElementById("voltY").innerHTML = fields["voltage_y"];
            document.getElementById("powerB").innerHTML = fields["power_b"];
            document.getElementById("ampB").innerHTML = fields["currents_b"];
            document.getElementById("voltB").innerHTML = fields["voltage_b"];
            document.getElementById("hourly").innerHTML = fields["hourly"];
            document.getElementById("day").innerHTML = fields["days"];
            document.getElementById("temp").innerHTML = fields["temp"];
            document.getElementById("station").innerHTML = fields["station_code"];

               }
            });

        }, 2500); 
   
});
 /*
    $(document).ready(function () {  
        $('#autoload').dataTable({ 
            
            "ajax": {  
                "url": "/iotSolar_proj/auto",  
                "type": "GET",  
                "datatype": "json"  
            },  
            "columns": [  
                { "numSerial.hourly": "Time" },  
                { "numSerial.voltage": "Voltage" },  
                { "numSerial.currents": "Current" },  
                { "numSerial.power": "Power" },  
                { "numSerial.temp": "Temp" } , 
                { "numSerial.intensity": "Intensity" } 
                

                    $("#hourly").load(numSerial.hourly); 
                    $("#voltage").load(numSerial.voltage); 
                    $("#currents").load(numSerial.currents); 
                    $("#temp").load(numSerial.temp); 
                    $("#days").load(numSerial.days); 
                    $("#power").load(numSerial.power); 
                    $("#intensity").load(numSerial.intensity); 
                    
            ]  
        });  
    });
*/

/*
    $(document).ready(function(){

        setInterval(function() {
                $.ajax({
                "url": "/smart-power-network/spower",
                "type": "GET",
                "datatype": "json",
                success: function (response) { 
                let pr = JSON.parse(response["power_r"]);
                let py = JSON.parse(response["power_y"]);
                let pb = JSON.parse(response["power_b"]);
                let temp = JSON.parse(response["temp"]);
                let sta = JSON.parse(response["station_code"]);
                let tm = JSON.parse(response["times"]);
                
                console.log(instanc)

                document.getElementById("pr").innerHTML = pr;  
                document.getElementById("py").innerHTML =py;
                document.getElementById("pb").innerHTML = pb;
                document.getElementById("temp").innerHTML = temp;
                document.getElementById("sta").innerHTML = sta;
                document.getElementById("tm").innerHTML = tm;

                }
                });    
            }, 2500); 
    });
 */   

