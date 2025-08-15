package com.belch.database;

import java.sql.*;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;

/**
 * Wrapper for database connections that automatically returns them to the pool when closed.
 * This allows transparent connection pooling without changing existing code.
 */
public class PooledConnection implements Connection {
    
    private final Connection delegateConnection;
    private final ConnectionPool connectionPool;
    private boolean closed = false;
    
    public PooledConnection(Connection connection, ConnectionPool pool) {
        this.delegateConnection = connection;
        this.connectionPool = pool;
    }
    
    @Override
    public void close() throws SQLException {
        if (!closed) {
            closed = true;
            // Return connection to pool instead of actually closing it
            connectionPool.returnConnection(delegateConnection);
        }
    }
    
    @Override
    public boolean isClosed() throws SQLException {
        return closed || delegateConnection.isClosed();
    }
    
    // Delegate all other methods to the underlying connection
    
    @Override
    public Statement createStatement() throws SQLException {
        checkClosed();
        return delegateConnection.createStatement();
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql);
    }
    
    @Override
    public CallableStatement prepareCall(String sql) throws SQLException {
        checkClosed();
        return delegateConnection.prepareCall(sql);
    }
    
    @Override
    public String nativeSQL(String sql) throws SQLException {
        checkClosed();
        return delegateConnection.nativeSQL(sql);
    }
    
    @Override
    public void setAutoCommit(boolean autoCommit) throws SQLException {
        checkClosed();
        delegateConnection.setAutoCommit(autoCommit);
    }
    
    @Override
    public boolean getAutoCommit() throws SQLException {
        checkClosed();
        return delegateConnection.getAutoCommit();
    }
    
    @Override
    public void commit() throws SQLException {
        checkClosed();
        delegateConnection.commit();
    }
    
    @Override
    public void rollback() throws SQLException {
        checkClosed();
        delegateConnection.rollback();
    }
    
    @Override
    public DatabaseMetaData getMetaData() throws SQLException {
        checkClosed();
        return delegateConnection.getMetaData();
    }
    
    @Override
    public void setReadOnly(boolean readOnly) throws SQLException {
        checkClosed();
        delegateConnection.setReadOnly(readOnly);
    }
    
    @Override
    public boolean isReadOnly() throws SQLException {
        checkClosed();
        return delegateConnection.isReadOnly();
    }
    
    @Override
    public void setCatalog(String catalog) throws SQLException {
        checkClosed();
        delegateConnection.setCatalog(catalog);
    }
    
    @Override
    public String getCatalog() throws SQLException {
        checkClosed();
        return delegateConnection.getCatalog();
    }
    
    @Override
    public void setTransactionIsolation(int level) throws SQLException {
        checkClosed();
        delegateConnection.setTransactionIsolation(level);
    }
    
    @Override
    public int getTransactionIsolation() throws SQLException {
        checkClosed();
        return delegateConnection.getTransactionIsolation();
    }
    
    @Override
    public SQLWarning getWarnings() throws SQLException {
        checkClosed();
        return delegateConnection.getWarnings();
    }
    
    @Override
    public void clearWarnings() throws SQLException {
        checkClosed();
        delegateConnection.clearWarnings();
    }
    
    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency) throws SQLException {
        checkClosed();
        return delegateConnection.createStatement(resultSetType, resultSetConcurrency);
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql, resultSetType, resultSetConcurrency);
    }
    
    @Override
    public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency) throws SQLException {
        checkClosed();
        return delegateConnection.prepareCall(sql, resultSetType, resultSetConcurrency);
    }
    
    @Override
    public Map<String, Class<?>> getTypeMap() throws SQLException {
        checkClosed();
        return delegateConnection.getTypeMap();
    }
    
    @Override
    public void setTypeMap(Map<String, Class<?>> map) throws SQLException {
        checkClosed();
        delegateConnection.setTypeMap(map);
    }
    
    @Override
    public void setHoldability(int holdability) throws SQLException {
        checkClosed();
        delegateConnection.setHoldability(holdability);
    }
    
    @Override
    public int getHoldability() throws SQLException {
        checkClosed();
        return delegateConnection.getHoldability();
    }
    
    @Override
    public Savepoint setSavepoint() throws SQLException {
        checkClosed();
        return delegateConnection.setSavepoint();
    }
    
    @Override
    public Savepoint setSavepoint(String name) throws SQLException {
        checkClosed();
        return delegateConnection.setSavepoint(name);
    }
    
    @Override
    public void rollback(Savepoint savepoint) throws SQLException {
        checkClosed();
        delegateConnection.rollback(savepoint);
    }
    
    @Override
    public void releaseSavepoint(Savepoint savepoint) throws SQLException {
        checkClosed();
        delegateConnection.releaseSavepoint(savepoint);
    }
    
    @Override
    public Statement createStatement(int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
        checkClosed();
        return delegateConnection.createStatement(resultSetType, resultSetConcurrency, resultSetHoldability);
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
    }
    
    @Override
    public CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException {
        checkClosed();
        return delegateConnection.prepareCall(sql, resultSetType, resultSetConcurrency, resultSetHoldability);
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql, int autoGeneratedKeys) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql, autoGeneratedKeys);
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql, int[] columnIndexes) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql, columnIndexes);
    }
    
    @Override
    public PreparedStatement prepareStatement(String sql, String[] columnNames) throws SQLException {
        checkClosed();
        return delegateConnection.prepareStatement(sql, columnNames);
    }
    
    @Override
    public Clob createClob() throws SQLException {
        checkClosed();
        return delegateConnection.createClob();
    }
    
    @Override
    public Blob createBlob() throws SQLException {
        checkClosed();
        return delegateConnection.createBlob();
    }
    
    @Override
    public NClob createNClob() throws SQLException {
        checkClosed();
        return delegateConnection.createNClob();
    }
    
    @Override
    public SQLXML createSQLXML() throws SQLException {
        checkClosed();
        return delegateConnection.createSQLXML();
    }
    
    @Override
    public boolean isValid(int timeout) throws SQLException {
        if (closed) return false;
        return delegateConnection.isValid(timeout);
    }
    
    @Override
    public void setClientInfo(String name, String value) throws SQLClientInfoException {
        try {
            checkClosed();
            delegateConnection.setClientInfo(name, value);
        } catch (SQLException e) {
            throw new SQLClientInfoException();
        }
    }
    
    @Override
    public void setClientInfo(Properties properties) throws SQLClientInfoException {
        try {
            checkClosed();
            delegateConnection.setClientInfo(properties);
        } catch (SQLException e) {
            throw new SQLClientInfoException();
        }
    }
    
    @Override
    public String getClientInfo(String name) throws SQLException {
        checkClosed();
        return delegateConnection.getClientInfo(name);
    }
    
    @Override
    public Properties getClientInfo() throws SQLException {
        checkClosed();
        return delegateConnection.getClientInfo();
    }
    
    @Override
    public Array createArrayOf(String typeName, Object[] elements) throws SQLException {
        checkClosed();
        return delegateConnection.createArrayOf(typeName, elements);
    }
    
    @Override
    public Struct createStruct(String typeName, Object[] attributes) throws SQLException {
        checkClosed();
        return delegateConnection.createStruct(typeName, attributes);
    }
    
    @Override
    public void setSchema(String schema) throws SQLException {
        checkClosed();
        delegateConnection.setSchema(schema);
    }
    
    @Override
    public String getSchema() throws SQLException {
        checkClosed();
        return delegateConnection.getSchema();
    }
    
    @Override
    public void abort(Executor executor) throws SQLException {
        checkClosed();
        delegateConnection.abort(executor);
    }
    
    @Override
    public void setNetworkTimeout(Executor executor, int milliseconds) throws SQLException {
        checkClosed();
        delegateConnection.setNetworkTimeout(executor, milliseconds);
    }
    
    @Override
    public int getNetworkTimeout() throws SQLException {
        checkClosed();
        return delegateConnection.getNetworkTimeout();
    }
    
    @Override
    public <T> T unwrap(Class<T> iface) throws SQLException {
        checkClosed();
        return delegateConnection.unwrap(iface);
    }
    
    @Override
    public boolean isWrapperFor(Class<?> iface) throws SQLException {
        checkClosed();
        return delegateConnection.isWrapperFor(iface);
    }
    
    private void checkClosed() throws SQLException {
        if (closed) {
            throw new SQLException("Connection has been closed");
        }
    }
}