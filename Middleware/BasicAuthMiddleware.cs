using System.Text;

namespace TestBasicAuth.Middleware
{
    public class BasicAuthMiddleware
    {
        private readonly RequestDelegate _next;

        public BasicAuthMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            //verificar si existe el header de autorización
            if (!context.Request.Headers.ContainsKey("Authorization"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("No se han proporcionado credenciales de autenticación");
                return;
            }

            //obtener el header de autorización y decodificarlo
            var authHeader = context.Request.Headers["Authorization"].ToString();
            if(authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var encodedCredencials = authHeader.Substring("Basic ".Length).Trim();
                var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredencials));

                //extraer el usuario y la contraseña
                var parts = decodedCredentials.Split(':', 2);

                var username = parts[0];
                var password = parts[1];

                //verificar si el usuario y la contraseña son correctos
                if(username.Equals("admin") && password.Equals("admin"))
                {
                    await _next(context); //continuar con el siguiente middleware
                    return;
                }
            }

            //si el usuario y la contraseña no son correctos
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Credenciales de autenticación inválidas");
        }
    }
}
