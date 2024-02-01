
$(document).ready(function(){
    setInterval(function () {
    
        const $currentChart = $("#currentChartt");
        $.ajax({
          url: $currentChart.data("url"),
          success: function (data) {
    
            const ctx1 = $currentChart[0].getContext("2d");
            new Chart(ctx1, {
              type: 'line',
              data: {
                labels: data.labels,
                datasets: [{
                  label: ' Red',
                  borderColor: 'rgba(247, 33, 97, 0.8)',
                  backgroundColor: 'rgba(247, 33, 97, 0.5)',
                  pointBorderColor: 'rgba(247, 33, 97, 0)',
                  pointBackgroundColor: 'rgba(247, 33, 97, 0.8)',
                  pointBorderWidth: 1,
                  data: data.amp_r
                },{
                    label: ' Yellow',
                    borderColor: 'rgbargba(247, 232, 33, 0.75)',
                    backgroundColor: 'rgba(247, 232, 33, 0.3)',
                    pointBorderColor: 'rgba(247, 232, 33, 0)',
                    pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                    pointBorderWidth: 1,
                    data: data.amp_y
                  },{
                    label: 'Blue',
                    borderColor: 'rgba(33, 83, 247, 0.75)',
                    backgroundColor: 'rgba(33, 83, 247, 0.3)',
                    pointBorderColor: 'rgba(33, 83, 247, 0)',
                    pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                    pointBorderWidth: 1,
                    data: data.amp_b
                  }
                ]          
              },
              options: {
                responsive: true,
                legend: {
                  position: 'top',
                },
                title: {
                  display: true,
                  text: 'current Chart'
                }
              }
            });					  
      
          }
        });
    
    }, 11250);
    });
    
       
    $(document).ready(function(){
        setInterval(function () {
        
            const $voltageChart = $("#voltageChartt");
            $.ajax({
                url: $voltageChart.data("url"),
              "type": "GET",
              "datatype": "json",
              success: function (data) {
                const ctx2 = $voltageChart[0].getContext("2d");
                new Chart(ctx2, {
                  type: 'line',
                  data: {
                    labels: data.labels,
                    datasets: [{
                      label: ' Red ',
                      borderColor: 'rgba(247, 33, 97, 0.8)',
                      backgroundColor: 'rgba(247, 33, 97, 0.5)',
                      pointBorderColor: 'rgba(247, 33, 97, 0)',
                      pointBackgroundColor: 'rgba(247, 33, 97, 0.8)',
                      pointBorderWidth: 1,
                      data: data.volt_r
                    },{
                        label: ' Yellow',
                        borderColor: 'rgbargba(247, 232, 33, 0.75)',
                        backgroundColor: 'rgba(247, 232, 33, 0.3)',
                        pointBorderColor: 'rgba(247, 232, 33, 0)',
                        pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                        pointBorderWidth: 1,
                        data: data.volt_y
                      },{
                        label: 'Blue',
                        borderColor: 'rgba(33, 83, 247, 0.75)',
                        backgroundColor: 'rgba(33, 83, 247, 0.3)',
                        pointBorderColor: 'rgba(33, 83, 247, 0)',
                        pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                        pointBorderWidth: 1,
                        data: data.volt_b
                      }
                    ]          
                  },
                  options: {
                    responsive: true,
                    legend: {
                      position: 'top',
                    },
                    title: {
                      display: true,
                      text: 'Voltage Chart'
                    }
                  }
                });					  
          
              }
            });
        
        }, 11250);
        });
       
    $(document).ready(function(){
        setInterval(function () {
        
            const $powerChart = $("#powerChartt");
            $.ajax({
                url: $powerChart.data("url"),
              "type": "GET",
              "datatype": "json",
              success: function (data) {
                const ctx3 = $powerChart[0].getContext("2d");
                new Chart(ctx3, {
                  type: 'line',
                  data: {
                    labels: data.labels,
                    datasets: [{
                      label: ' Red',
                      borderColor: 'rgba(247, 33, 97, 0.8)',
                      backgroundColor: 'rgba(247, 33, 97, 0.5)',
                      pointBorderColor: 'rgba(247, 33, 97, 0)',
                      pointBackgroundColor: 'rgba(247, 33, 97, 0.8)',
                      pointBorderWidth: 1,
                      data: data.av_r
                    },{
                        label: 'Yellow',
                        borderColor: 'rgbargba(247, 232, 33, 0.75)',
                        backgroundColor: 'rgba(247, 232, 33, 0.3)',
                        pointBorderColor: 'rgba(247, 232, 33, 0)',
                        pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                        pointBorderWidth: 1,
                        data: data.av_y
                      },{
                        label: 'Blue',
                        borderColor: 'rgba(33, 83, 247, 0.75)',
                        backgroundColor: 'rgba(33, 83, 247, 0.3)',
                        pointBorderColor: 'rgba(33, 83, 247, 0)',
                        pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                        pointBorderWidth: 1,
                        data: data.av_b
                      }
                    ]          
                  },
                  options: {
                    responsive: true,
                    legend: {
                      position: 'top',
                    },
                    title: {
                      display: true,
                      text: 'Power Chart'
                    }
                  }
                });					  
          
              }
            });
        
        }, 11250);
        });
        


        $(document).ready(function(){

            setInterval(function() {
              const $auto_up = $("#autoauto");
                    $.ajax({
                     
                      url: $auto_up.data("url"),
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