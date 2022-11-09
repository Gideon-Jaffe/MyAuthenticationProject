package Controllers;

import com.google.gson.Gson;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

class UserRepository {
    private static volatile UserRepository userRepo;
    Map<String, User> usersCache;

    static String FILE_DIRECTORY = "./users/";

    static UserRepository getInstance() {

        UserRepository result = userRepo;

        if (result == null) {
            synchronized (UserRepository.class) {
                result = userRepo;
                if (result == null) {
                    userRepo = result = new UserRepository();
                }
            }
        }
        return result;
    }

    private UserRepository() {

        usersCache = new HashMap<>();
        loadAllUsersToCache(new File(FILE_DIRECTORY));
    }

    User readFromCache(String email){
        return usersCache.get(email);
    }

    private void loadAllUsersToCache(File folder) {
        for (File fileEntry: folder.listFiles()) {
            if (!fileEntry.isDirectory()) {
                if (Utils.isJsonFile(fileEntry)) {
                    User user = readFromFile(fileEntry.getAbsolutePath());
                    usersCache.put(user.getEmail(),user);
                }
            }
        }
    }

    void deleteFile(String path) {
        File file = new File(FILE_DIRECTORY + path);
        boolean b= file.delete();
    }

    void deleteFile(User user) {
        if (!usersCache.containsKey(user.getEmail())) {
            throw new IllegalArgumentException("cant remove user that doesnt exist");
        }
        usersCache.remove(user.getEmail());
        deleteFile(user.getEmail() + ".json");
    }

    void writeToFile(String fileName, User user) throws IOException {
        Gson gson = new Gson();
        try (FileWriter fw = new FileWriter(FILE_DIRECTORY + fileName)) {
            String userJson = gson.toJson(user);
            fw.write(userJson);
            usersCache.put(user.getEmail(), user);
        } catch (IOException e) {
            throw new IOException("cant write to new file to update");
        }
    }

    private User readFromFile(String fileName) {

        User readUser = null;
        try (FileReader fr = new FileReader(fileName)) {
            Gson gson = new Gson();
            readUser = gson.fromJson(fr, User.class);
            usersCache.put(readUser.getEmail(), readUser);
        } catch(FileNotFoundException e) {
            throw new RuntimeException("file not found");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return readUser;
    }
}
