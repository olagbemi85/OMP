/*
const usernameField = document.querySelector("#usernameField");

usernameField.addEventListener("keyup", (e) =>{
	
	console.log("77", 77);
	const usernameVal = e.target.value;

		console.log("usernameVal", usernameVal);
	});
*/
const feedBackArea = document.querySelector(".invalid_feedback");
const usernameField = document.querySelector("#usernameField");
const emailField = document.querySelector("#emailField");
const passwordField = document.querySelector("#passwordField");
const emailfeedBackArea = document.querySelector(".emailfeedBackArea");
const usernamesuccessOutput = document.querySelector(".usernamesuccessOutput");
const emailsuccessOutput = document.querySelector(".emailsuccessOutput");
const showPasswordToggle = document.querySelector(".showPasswordToggle");
const submitBtn = document.querySelector(".submitBtn");

const handleToggleInput=(e)=>{  
	if(showPasswordToggle.textContent === "SHOW"){
		showPasswordToggle.textContent = "HIDE";
		passwordField.setAttribute("type", "text");
	}else{
		showPasswordToggle.textContent = "SHOW";
		passwordField.setAttribute("type", "password");
	}
}


showPasswordToggle.addEventListener('click', handleToggleInput);


usernameField.addEventListener("keyup", (e) =>{
  
  //console.log("77", 77);
  const usernameVal = e.target.value;

  usernamesuccessOutput.style.display='block';
  usernamesuccessOutput.textContent= `Checking ${usernameVal}`;

  usernameField.classList.remove('is_invalid');
  feedBackArea.style.display='none';

  if(usernameVal.length > 0){
  fetch("/authentication/validate-username", {
    body: JSON.stringify({ username: usernameVal }),
    method: "POST",
  })
  .then(res => res.json())
  .then(data => {
    console.log("data", data);
    usernamesuccessOutput.style.display='none';
    if(data.username_error){
      submitBtn.setAttribute("disabled", "disabled");
      submitBtn.disabled = true;	
      usernameField.classList.add('is_invalid');
      feedBackArea.style.display='block';
      feedBackArea.innerHTML=`<p>${data.username_error}</p>`;
    }else{submitBtn.removeAttribute("disabled");}
  });
}
});


emailField.addEventListener("keyup", (a) =>{
  const emailVal = a.target.value;
  emailsuccessOutput.style.display='block';
  emailsuccessOutput.textContent= `Checking ${emailVal}`;

  emailField.classList.remove('is_invalid');
  emailfeedBackArea.style.display='none';

  if(emailVal.length > 0){
  fetch("/authentication/validate-email", {
    body: JSON.stringify({ email: emailVal }),
    method: "POST",
  })
  .then(res => res.json())
  .then(data => {
    console.log("data", data);
    if(data.email_error){
      submitBtn.disabled = true;	
      emailField.classList.add('is_invalid');
      emailsuccessOutput.style.display = 'none';
      emailfeedBackArea.style.display='block';
      emailfeedBackArea.innerHTML=`<p>${data.email_error}</p>`;
    }else{submitBtn.removeAttribute("disabled");
	}	
  });
}
});

