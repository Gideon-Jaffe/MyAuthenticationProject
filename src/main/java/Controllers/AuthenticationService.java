package Controllers;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.InvalidParameterException;
import java.util.*;

class AuthenticationService {

    static int id = 0;
    Map<String, User> userTokens;

    public static void register(String email, String name, String password) {

        if (!checkIfUserExists(email)) {
            User user = new User(id++, email, name, password);
            try {
                BufferedWriter output = new BufferedWriter(new FileWriter(email + ".json"));
                output.write(new Gson().toJson(user));
            } catch (IOException e) {
                System.out.println("Couldn't write to file");
                throw new RuntimeException(e);
            }
        }
    }

    public AuthenticationService() {
        this.userTokens = new HashMap<>();
    }

    String login(String email, String password) {
        try (FileReader reader = new FileReader(email + ".json")) {
            Gson gson = new Gson();
            User myUser = gson.fromJson(reader, User.class);
            if (Objects.equals(myUser.getPassword(), password)) {
                return createToken(myUser);
            } else {
                throw new InvalidParameterException("Password incorrect");
            }
        } catch (FileNotFoundException e) {
            throw new InvalidParameterException("User does not exist");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String createToken(User user) {
        String token = UUID.randomUUID().toString();
        userTokens.put(token, user);
        return token;
    }


    private static boolean checkIfUserExists(String email) {
        try (FileReader fr = new FileReader(email + ".json")) {
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return true;
    }
}

