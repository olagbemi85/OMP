


$(document).ready(function(){
    $("small").click(function(){
        if($("#togglText").text() === "SHOW"){
            $("#password").attr("type","text");// Changing type attribute
            $("#togglText").text("HIDE");
        }   
        else{
            $("#password").attr("type","password");// Changing type attribute 
            $("#togglText").text("SHOW"); // Change the Text
           } 
    });
    
});

$(document).ready(function(){
    $("#toggle").change(function(){
     
     // Check the checkbox state
     if($(this).is(':checked')){
      // Changing type attribute
      $("#password").attr("type","text");
      
      // Change the Text
      $("#toggleText").text("Hide");
     }else{
      // Changing type attribute
      $("#password").attr("type","password");
     
      // Change the Text
      $("#toggleText").text("Show");
     }
    
    });
   });
