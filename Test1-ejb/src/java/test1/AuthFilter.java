import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.*;
 
@WebFilter("/*")
public class AuthFilter implements Filter {
 
    private static List<Rule> rules = new ArrayList<Rule>();
    private static final String PARAM_TOKEN = "token";
    private static final String PARAM_LOGIN = "login";
    private static final String PARAM_PASS = "pass";
 
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        BufferedReader res = new BufferedReader(new InputStreamReader(filterConfig.getServletContext().getResourceAsStream("/WEB-INF/classes/users.txt")));
        try {
            String tmp;
            while ((tmp=res.readLine())!=null) {
                String[] strings = tmp.split("~");
                if (strings.length==3) rules.add(new Rule(strings[0], strings[1], strings[2].split(",")));
            }
        } catch (IOException ioe) {
            System.err.println("access rules not loaded!");
            ioe.printStackTrace();
        }
    }
 
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        String uri = ((HttpServletRequest) req).getRequestURI();
        boolean rez = false;
        for (Rule r : rules) {
            if (r.isApply(uri) && auth((HttpServletRequest)req, r)) {
                rez = true;
                break;
            }
        }
        if (rez) chain.doFilter(req, resp);
        else {
            PrintWriter out = resp.getWriter();
            out.print("<html><body><form method=\"POST\" action=\"" + uri + "\">\n" +
                    "<input type=\"text\" name=\""+PARAM_LOGIN+"\" placeholder=\"Login\"><br/>\n" +
                    "<input type=\"password\" name=\""+PARAM_PASS+"\" placeholder=\"Password\"><br/>\n" +
                    "<input type=\"submit\" value=\"Login\" />\n" +
                    "</form></body></html>");
            out.flush();
            out.close();
        }
    }
 
    @Override
    public void destroy() {}
 
    public boolean auth(HttpServletRequest req, Rule r) {
        if (Rule.USER_ANY.equals(r.user)) return true;
        String reqUser = getStoredUser(req);
        String reqLogin = req.getParameter(PARAM_LOGIN);
        String reqPass = req.getParameter(PARAM_PASS);
        if (reqUser!=null && reqUser.equals(r.user)) {
            return true;
        }
        if(reqLogin!=null && reqPass!=null && r.check(reqLogin, reqPass)) {
            storeUser(req, reqLogin);
            return true;
        }
        return false;
    }
 
    private String getStoredUser(HttpServletRequest req) {
        return (String) req.getSession().getAttribute(PARAM_TOKEN);
    }
 
    private void storeUser(HttpServletRequest req, String user) {
        req.getSession(true).setAttribute(PARAM_TOKEN, user);
    }
 
    private class Rule {
        public static final String USER_ANY = "*";
        public static final String URL_ANY = "/*";
        String user, password;
        String[] access;
 
        private Rule(String user, String password, String[] access) {
            this.user = user;
            this.password = password;
            this.access = access;
        }
 
        public boolean isApply(String uri) {
            for (String a : access) if (URL_ANY.equals(a) || a.equals(uri)) return true;
            return false;
        }
 
        public boolean check(String login, String pass) {
            return USER_ANY.equals(this.user) || (login.equals(this.user) && pass.equals(this.password));
        }
    }
}