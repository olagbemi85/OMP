
$(document).ready(function(){
setInterval(function () {

    const $currentChart = $("#currentChart");
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
              data: data.data_r
            },{
                label: ' Yellow',
                borderColor: 'rgbargba(247, 232, 33, 0.75)',
                backgroundColor: 'rgba(247, 232, 33, 0.3)',
                pointBorderColor: 'rgba(247, 232, 33, 0)',
                pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                pointBorderWidth: 1,
                data: data.data_y
              },{
                label: 'Blue',
                borderColor: 'rgba(33, 83, 247, 0.75)',
                backgroundColor: 'rgba(33, 83, 247, 0.3)',
                pointBorderColor: 'rgba(33, 83, 247, 0)',
                pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                pointBorderWidth: 1,
                data: data.data_b
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
    
        const $voltageChart = $("#voltageChart");
        $.ajax({
          "url": "/smart-power-network/voltageChart",
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
                  data: data.data_r
                },{
                    label: ' Yellow',
                    borderColor: 'rgbargba(247, 232, 33, 0.75)',
                    backgroundColor: 'rgba(247, 232, 33, 0.3)',
                    pointBorderColor: 'rgba(247, 232, 33, 0)',
                    pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                    pointBorderWidth: 1,
                    data: data.data_y
                  },{
                    label: 'Blue',
                    borderColor: 'rgba(33, 83, 247, 0.75)',
                    backgroundColor: 'rgba(33, 83, 247, 0.3)',
                    pointBorderColor: 'rgba(33, 83, 247, 0)',
                    pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                    pointBorderWidth: 1,
                    data: data.data_b
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
    
        const $powerChart = $("#powerChart");
        $.ajax({
          "url": "/smart-power-network/powerChart",
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
                  data: data.data_r
                },{
                    label: 'Yellow',
                    borderColor: 'rgbargba(247, 232, 33, 0.75)',
                    backgroundColor: 'rgba(247, 232, 33, 0.3)',
                    pointBorderColor: 'rgba(247, 232, 33, 0)',
                    pointBackgroundColor: 'rgba(247, 232, 33, 0.9)',
                    pointBorderWidth: 1,
                    data: data.data_y
                  },{
                    label: 'Blue',
                    borderColor: 'rgba(33, 83, 247, 0.75)',
                    backgroundColor: 'rgba(33, 83, 247, 0.3)',
                    pointBorderColor: 'rgba(33, 83, 247, 0)',
                    pointBackgroundColor: 'rgba(33, 83, 247, 0.9)',
                    pointBorderWidth: 1,
                    data: data.data_b
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
    //Real time ==========================================================================================
    //var data = [], totalPoints = 110;
   
 /*   $.ajax({
        "url": "/smart-power-network/tempChart",
        "type": "GET",
        "datatype": "json",
        success: function (response) {
 
         var data1 = response[data]
         var data2 = response['data']
            var updateInterval = 320;
            var realtime = 'on';     
            let data
           
    
    var plot = $.plot('#', [getRandomData()], {
        series: {
            shadowSize: 0,
            color: 'rgb(0, 188, 212)'
        },
        grid: {
            borderColor: '#f3f3f3',
            borderWidth: 1,
            tickColor: '#f3f3f3'
        },
        lines: {
            fill: true
        },
        yaxis: {
            min: 0,
            max: 100
        },
        xaxis: {
            min: 0,
            max: 100
        }
    });

    function updateRealTime() {
        plot.setData([getRandomData()]);
        plot.draw();

        var timeout;
        if (realtime === 'on') {
            timeout = setTimeout(updateRealTime, updateInterval);
        } else {
            clearTimeout(timeout);
        }
    }

    updateRealTime();

    $('#realtime').on('change', function () {
        realtime = this.checked ? 'on' : 'off';
        updateRealTime();
    });

}
})  */

});


/*
   
$(function () {
const ctx = document.getElementById('mc');

new Chart(ctx, {
  type: 'bar',
  data: {
    labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple', 'Orange'],
    datasets: [{
      label: '# of Votes',
      data: [12, 19, 3, 5, 2, 3],
      borderWidth: 1
    }]
  },
  options: {
    scales: {
      y: {
        beginAtZero: true
      }
    }
  }
}); 
});
*/