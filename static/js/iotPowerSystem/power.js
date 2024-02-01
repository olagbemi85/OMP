
                $(document).ready(function(){
                    setInterval(function() {
                        const $auto_up = $("#{{s.code}}");
                            $.ajax({
                            
                                url: $auto_up.data("url"),
                                "type": "GET",
                                "datatype": "json",
                                success: function (response) { 
                                var value = JSON.parse(response["numSerial"]);
                                var code = JSON.parse(response["s_code"]);
                                //console.log(value);
                                var propertyName = 'width';
                                $(".progresS").css(propertyName, value);
                                $("h4.tx").text(value);
                                }
                            });                
                        }, 250);                 
                });    
            