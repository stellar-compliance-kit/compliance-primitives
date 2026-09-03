declare module "sql.js/dist/sql-asm.js" {
  import type { SqlJsStatic } from "sql.js";
  const initSqlJs: (config?: unknown) => Promise<SqlJsStatic>;
  export default initSqlJs;
}
