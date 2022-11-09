package Controllers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthenticationController {
     AuthenticationService authService;

    static Logger log = LogManager.getLogger(AuthenticationController.class.getName());

    public AuthenticationController() {
        this.authService = AuthenticationService.getInstance();
    }

    public String login(String email, String password) {
        log.info("starting login with email " + email + " and password " + password);
        Utils.checkEmail(email);
        Utils.checkPassword(password);
        return authService.login(email, password);
    }

    public void register(String email, String name, String password) {
        Utils.checkEmail(email);
        Utils.checkName(name);
        Utils.checkPassword(password);
        authService.register(email, name, password);
    }
}

