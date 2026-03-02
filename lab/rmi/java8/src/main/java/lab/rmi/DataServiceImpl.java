package lab.rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataServiceImpl extends UnicastRemoteObject implements DataService {

    private static final long serialVersionUID = 1L;

    private static final Map<String, String> USER_DB = new HashMap<String, String>();

    static {
        USER_DB.put("admin",     "Administrator|admin@corp.local|ROLE_ADMIN");
        USER_DB.put("user1",     "John Doe|jdoe@corp.local|ROLE_USER");
        USER_DB.put("svc_batch", "Batch Service|batch@corp.local|ROLE_SERVICE");
    }

    public DataServiceImpl(int port) throws RemoteException {
        super(port);
    }

    @Override
    public List<String> getUsers() throws RemoteException {
        return Arrays.asList("admin", "user1", "svc_batch");
    }

    @Override
    public String getUserData(String userId) throws RemoteException {
        String data = USER_DB.get(userId);
        return data != null ? data : "NOT_FOUND";
    }
}
